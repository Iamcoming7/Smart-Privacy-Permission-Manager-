// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

contract Project {
    struct AppPermission {
        string appName;
        string appId;
        bool contactAccessGranted;
        uint256 grantedTimestamp;
        uint256 lastAccessTimestamp;
        uint256 accessCount;
        bool isActive;
    }
    
    struct PermissionAlert {
        string appId;
        string alertType; // "UNUSUAL_REQUEST", "EXCESSIVE_ACCESS", "SUSPICIOUS_ACTIVITY"
        string description;
        uint256 timestamp;
        bool acknowledged;
    }
    
    mapping(address => mapping(string => AppPermission)) public userAppPermissions;
    mapping(address => PermissionAlert[]) public userAlerts;
    mapping(address => string[]) public userAppIds;
    
    event PermissionGranted(address indexed user, string appId, string appName);
    event PermissionRevoked(address indexed user, string appId, string appName);
    event ContactAccessed(address indexed user, string appId, uint256 timestamp);
    event AlertTriggered(address indexed user, string appId, string alertType);
    event AlertAcknowledged(address indexed user, uint256 alertIndex);
    
    modifier onlyPermissionOwner(string memory appId) {
        require(
            userAppPermissions[msg.sender][appId].isActive,
            "Permission not found or inactive"
        );
        _;
    }
    
    // Core Function 1: Grant Permission to App
    function grantPermission(
        string memory appId,
        string memory appName
    ) external {
        require(bytes(appId).length > 0, "App ID cannot be empty");
        require(bytes(appName).length > 0, "App name cannot be empty");
        
        AppPermission storage permission = userAppPermissions[msg.sender][appId];
        
        // If this is a new app, add to user's app list
        if (!permission.isActive) {
            userAppIds[msg.sender].push(appId);
        }
        
        permission.appName = appName;
        permission.appId = appId;
        permission.contactAccessGranted = true;
        permission.grantedTimestamp = block.timestamp;
        permission.isActive = true;
        
        emit PermissionGranted(msg.sender, appId, appName);
    }
    
    // Core Function 2: Record Contact Access and Monitor Usage
    function recordContactAccess(string memory appId) external onlyPermissionOwner(appId) {
        AppPermission storage permission = userAppPermissions[msg.sender][appId];
        
        require(permission.contactAccessGranted, "Contact access not granted");
        
        permission.lastAccessTimestamp = block.timestamp;
        permission.accessCount++;
        
        // Check for suspicious activity (more than 100 accesses in 24 hours)
        if (permission.accessCount > 100 && 
            block.timestamp - permission.grantedTimestamp < 86400) {
            _triggerAlert(
                appId,
                "EXCESSIVE_ACCESS",
                "App has accessed contacts more than 100 times in 24 hours"
            );
        }
        
        emit ContactAccessed(msg.sender, appId, block.timestamp);
    }
    
    // Core Function 3: Revoke Permission and Clean Up
    function revokePermission(string memory appId) external onlyPermissionOwner(appId) {
        AppPermission storage permission = userAppPermissions[msg.sender][appId];
        string memory appName = permission.appName;
        
        permission.contactAccessGranted = false;
        permission.isActive = false;
        
        // Remove from active apps list
        _removeAppFromList(appId);
        
        emit PermissionRevoked(msg.sender, appId, appName);
    }
    
    // Utility function to trigger alerts
    function _triggerAlert(
        string memory appId,
        string memory alertType,
        string memory description
    ) internal {
        PermissionAlert memory newAlert = PermissionAlert({
            appId: appId,
            alertType: alertType,
            description: description,
            timestamp: block.timestamp,
            acknowledged: false
        });
        
        userAlerts[msg.sender].push(newAlert);
        emit AlertTriggered(msg.sender, appId, alertType);
    }
    
    // Remove app from user's app list
    function _removeAppFromList(string memory appId) internal {
        string[] storage apps = userAppIds[msg.sender];
        for (uint i = 0; i < apps.length; i++) {
            if (keccak256(bytes(apps[i])) == keccak256(bytes(appId))) {
                apps[i] = apps[apps.length - 1];
                apps.pop();
                break;
            }
        }
    }
    
    // Acknowledge alert
    function acknowledgeAlert(uint256 alertIndex) external {
        require(alertIndex < userAlerts[msg.sender].length, "Invalid alert index");
        userAlerts[msg.sender][alertIndex].acknowledged = true;
        emit AlertAcknowledged(msg.sender, alertIndex);
    }
    
    // Get user's app permissions
    function getUserAppPermissions(address user) 
        external 
        view 
        returns (string[] memory) 
    {
        return userAppIds[user];
    }
    
    // Get specific app permission details
    function getAppPermissionDetails(address user, string memory appId) 
        external 
        view 
        returns (AppPermission memory) 
    {
        return userAppPermissions[user][appId];
    }
    
    // Get user alerts count
    function getUserAlertsCount(address user) external view returns (uint256) {
        return userAlerts[user].length;
    }
    
    // Get specific alert
    function getUserAlert(address user, uint256 index) 
        external 
        view 
        returns (PermissionAlert memory) 
    {
        require(index < userAlerts[user].length, "Invalid alert index");
        return userAlerts[user][index];
    }
}
