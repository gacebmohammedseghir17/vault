import pandas as pd
import lightgbm as lgb
from onnxmltools import convert_lightgbm
from onnxmltools.convert.common.data_types import FloatTensorType
import onnx
import os
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score

# CONFIGURATION
INPUT_CSV = "training_data.csv"
OUTPUT_ONNX = "opcode_model.onnx"
FEATURE_DIM = 4096

def force_tensor_output(onnx_model):
    """
    Surgically removes ZipMap AND updates the graph output signature 
    to strictly match what the Rust ndarray expects.
    """
    graph = onnx_model.graph
    nodes = graph.node
    zipmap_node = None
    
    # 1. Find ZipMap
    for node in nodes:
        if node.op_type == "ZipMap":
            zipmap_node = node
            break
            
    if zipmap_node:
        print("[*] Performing Graph Surgery on ZipMap...")
        prob_tensor_name = zipmap_node.input[0] # The raw float tensor
        map_name = zipmap_node.output[0]        # The dictionary output
        
        # 2. Remove the node
        nodes.remove(zipmap_node)
        
        # 3. Fix the Graph Output Signature
        for output in graph.output:
            if output.name == map_name:
                print(f"    - Redirecting output '{map_name}' -> '{prob_tensor_name}'")
                output.name = prob_tensor_name
                
                # CRITICAL FIX: Wipe the old 'Sequence<Map>' type definition
                output.type.Clear()
                
                # Set new type to Tensor<Float> [None, 2]
                tensor_type = output.type.tensor_type
                tensor_type.elem_type = onnx.TensorProto.FLOAT
                
                # Define Shape: [Batch_Size, Num_Classes]
                # Dim 0: Batch Size (Any)
                d0 = tensor_type.shape.dim.add()
                d0.dim_param = "batch"
                # Dim 1: Classes (2 -> Benign/Malware)
                d1 = tensor_type.shape.dim.add()
                d1.dim_value = 2
                
                print("    - Updated Graph Signature to Tensor<Float>")
                
    return onnx_model

def train_and_export():
    print(f"[*] Loading dataset: {INPUT_CSV}...")
    if not os.path.exists(INPUT_CSV):
        print(f"[!] ERROR: {INPUT_CSV} not found.")
        return

    try:
        # Load Data
        data = pd.read_csv(INPUT_CSV)
        X = data.iloc[:, :-1]
        y = data.iloc[:, -1]

        # Train
        print("[*] Training LightGBM Model...")
        clf = lgb.LGBMClassifier(n_estimators=100, learning_rate=0.1, num_leaves=31, random_state=42, n_jobs=-1)
        clf.fit(X, y)
        print(f"    - Accuracy: {clf.score(X, y)*100:.2f}%")

        # Convert
        print("[*] Converting to ONNX...")
        initial_types = [('float_input', FloatTensorType([None, FEATURE_DIM]))]
        onnx_model = convert_lightgbm(clf, initial_types=initial_types, target_opset=12)

        # Fix Graph
        onnx_model = force_tensor_output(onnx_model)

        # Save
        with open(OUTPUT_ONNX, "wb") as f:
            f.write(onnx_model.SerializeToString())
            
        print(f"[SUCCESS] Fixed Brain saved to: {OUTPUT_ONNX}")

    except Exception as e:
        print(f"[!] FAILURE: {e}")

if __name__ == "__main__":
    train_and_export()