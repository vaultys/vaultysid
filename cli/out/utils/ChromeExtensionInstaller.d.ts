interface InstallerOptions {
    profileName?: string;
    chromeUserDataDir?: string | null;
    downloadDir?: string;
    keepDownloads?: boolean;
    autoDetect?: boolean;
    forceReinstall?: boolean;
    closeChrome?: boolean;
    logLevel?: "debug" | "info" | "warn" | "error";
    allProfiles?: boolean;
}
/**
 * Chrome Extension Installer
 * Installs extensions directly to the file system from a list of extension IDs
 */
export default class ChromeExtensionInstaller {
    private options;
    private extensionsDir;
    private userDataDir;
    constructor(options?: InstallerOptions);
    /**
     * Log messages based on log level
     * @param {string} level - Log level
     * @param {string} message - Message to log
     */
    log(level: "debug" | "info" | "warn" | "error", message: string): void;
    /**
     * Get the default Chrome user data directory based on the OS
     * @returns {string} Path to Chrome user data directory
     */
    getDefaultChromeUserDataDir(): string;
    /**
     * Check if Chrome is running
     * @returns {Promise<boolean>} True if Chrome is running
     */
    isChromeRunning(): Promise<boolean>;
    /**
     * Close Chrome browser
     * @returns {Promise<boolean>} True if Chrome was closed successfully
     */
    closeChrome(): Promise<boolean>;
    /**
     * Generate URL for downloading extension CRX file
     * @param {string} extensionId - Chrome extension ID
     * @returns {string} Download URL
     */
    getCrxDownloadUrl(extensionId: string): string;
    /**
     * Download extension CRX file
     * @param {string} extensionId - Chrome extension ID
     * @returns {Promise<string>} Path to downloaded file
     */
    downloadExtension(extensionId: string): Promise<string>;
    /**
     * Extract CRX file to extension directory
     * @param {string} crxFilePath - Path to CRX file
     * @param {string} extensionId - Chrome extension ID
     * @returns {Promise<string>} Path to extracted extension
     */
    extractExtension(crxFilePath: string, extensionId: string): Promise<string>;
    /**
     * Update Chrome preferences to enable the extension
     * @param {string} extensionId - Chrome extension ID
     */
    updateExtensionPreferences(extensionId: string): Promise<void>;
    /**
     * Check if an extension is already installed
     * @param {string} extensionId - Chrome extension ID
     * @returns {boolean} True if installed
     */
    isExtensionInstalled(extensionId: string): boolean;
    /**
     * Détecte tous les profils Chrome disponibles dans le répertoire utilisateur Chrome
     * @returns {string[]} Liste des noms de profils
     */
    getChromeProfiles(): string[];
    /**
     * Configure le profil actif pour les opérations d'installation
     * @param {string} profileName - Nom du profil à utiliser
     */
    setActiveProfile(profileName: string): void;
    /**
     * Install a single extension
     * @param {string} extensionId - Chrome extension ID
     * @returns {Promise<boolean>} Installation success
     */
    installExtension(extensionId: string): Promise<boolean>;
    /**
     * Install multiple extensions
     * @param {string[]} extensionIds - Array of extension IDs
     * @returns {Promise<Record<string, boolean>>} Installation results by extension ID
     */
    installExtensions(extensionIds: string[]): Promise<Record<string, boolean>>;
    /**
     * Clean up temporary files
     */
    cleanup(): void;
}
export {};
