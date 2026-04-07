rule QR_HTML_obfuscation 
{
    meta:
        author = "Ian Cook @cioaonk"
        date = "2025-01-01"
        description = "Matches on elements of an imageless QR Code rendered in HTML via a table"
        reference = "https://blog.delivr.to/delivr-tos-top-10-payloads-dec-24-pastejacking-image-less-qr-codes-and-concatenated-zip-a32e668106dd#b584 "
    strings:
        $back_color = "background-color:"
        $color = "color:"
        $white = "#FFFFFF" 
        $black = "#000000"
        $table = "<table>"
        $table_cell = "<td"

    condition:
        ($white and $black) and any of ($table, $table_cell) and any of ($back_color, $color)
}


