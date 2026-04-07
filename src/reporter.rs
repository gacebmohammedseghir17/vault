use printpdf::*;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, SmtpTransport, Transport};
use lettre::message::{MultiPart, Attachment};
use std::fs::{self, File};
use std::io::BufWriter;
use chrono::Local;
use ::image::io::Reader as ImageReader;

// --- CONFIGURATION ---
const SMTP_USERNAME: &str = "bigpomplemousse@gmail.com";
const SMTP_PASSWORD: &str = "auzhhmcbubozbytp"; 
const ADMIN_RECIPIENT: &str = "gaceb.mohammed.seghir@gmail.com";

pub fn generate_and_send_alert(pid: u32, process_name: &str, file_target: &str, reason: &str) {
    let timestamp = Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
    let filename = format!("ERDPS_Incident_{}.pdf", timestamp);

    println!("[*] GENERATING FORENSIC REPORT: {}...", filename);

    // --- SCOPE BLOCK: CREATE & CLOSE PDF ---
    {
        // Use a result block to catch errors without crashing
        let pdf_result = std::panic::catch_unwind(|| {
            let (doc, page1, layer1) = PdfDocument::new("ERDPS Forensic Report", Mm(210.0), Mm(297.0), "Layer 1");
            let current_layer = doc.get_page(page1).get_layer(layer1);
            let font = doc.add_builtin_font(BuiltinFont::Helvetica).unwrap();

            current_layer.use_text("ERDPS SECURITY ALERT", 24.0, Mm(20.0), Mm(270.0), &font);
            current_layer.use_text(format!("THREAT: {} (PID: {})", process_name, pid), 12.0, Mm(20.0), Mm(250.0), &font);
            current_layer.use_text(format!("REASON: {}", reason), 12.0, Mm(20.0), Mm(240.0), &font);
            current_layer.use_text(format!("TARGET: {}", file_target), 10.0, Mm(20.0), Mm(230.0), &font);

            // LOGO (Optional - Safe Load)
            if let Ok(image_file) = File::open("ERDPS LOGO.jpg") {
                if let Ok(reader) = ImageReader::new(std::io::BufReader::new(image_file)).with_guessed_format() {
                    if let Ok(decoded) = reader.decode() {
                        let image = Image::from_dynamic_image(&decoded);
                         // Using positional arguments for printpdf 0.3.2 compatibility
                         image.add_to_layer(
                             current_layer.clone(), 
                             Some(Mm(150.0)), 
                             Some(Mm(250.0)), 
                             None, 
                             Some(0.2), 
                             Some(0.2), 
                             None
                         );
                    }
                }
            }

            let file = File::create(&filename).expect("Failed to create PDF file");
            let mut writer = BufWriter::new(file);
            doc.save(&mut writer).expect("Failed to save PDF");
        });

        if pdf_result.is_err() {
            println!("[!] PDF Generation Failed. Skipping report.");
            return;
        }
    } // FILE IS CLOSED HERE AUTOMATICALLY

    // 2. SEND EMAIL (Safe Mode)
    println!("[*] SENDING EMAIL...");
    match send_email(&filename, process_name) {
        Ok(_) => {
            println!("[+] EMAIL SENT.");
            let _ = fs::remove_file(&filename);
        },
        Err(e) => {
            println!("[!] EMAIL FAILED: {}", e);
            // Do NOT panic. Just keep running.
        }
    }
}

fn send_email(filename: &str, threat_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let file_body = fs::read(filename)?;
    let content_type = lettre::message::header::ContentType::parse("application/pdf").unwrap();
    let filename_owned = String::from(filename);

    let email = Message::builder()
        .from(SMTP_USERNAME.parse()?)
        .to(ADMIN_RECIPIENT.parse()?)
        .subject(format!("ERDPS ALERT: {}", threat_name))
        .multipart(MultiPart::mixed().singlepart(Attachment::new(filename_owned).body(file_body, content_type)))?;

    let creds = Credentials::new(SMTP_USERNAME.to_string(), SMTP_PASSWORD.to_string());
    let mailer = SmtpTransport::relay("smtp.gmail.com")?.credentials(creds).build();
    mailer.send(&email)?;
    Ok(())
}
