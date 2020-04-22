rule record_call : app_assist
{
    meta:
        type = "privacy"
        category = "Access Audio"
        file_type = "Android"
        weight = "2.000"
		//Allows an application to record call conversation

    strings:        
	    $string1 = "Landroid/media/MediaRecorder;.setAudioSource:"
	    $string2 = "Landroid/media/MediaRecorder;.start:"
	    $string3 = "Landroid/media/MediaRecorder;.setOutputFormat:"	
	    $string4 = "Landroid/media/MediaRecorder;.release:" 
	
    condition:
        all of them
}

rule device_info_deviceid : app_assist 
{
    meta:
        type = "privacy"
        category = "Device Information"
        file_type = "Android"
        weight = "0.250"
		//Allows an application to retrieve device ID or IMEI

    strings:
        $dev_id1 = ".getDeviceID" nocase
        $dev_id2 = "ANDROID_ID" fullword        

    condition:
        1 of them
}

rule device_info_subscriberid : app_assist 
{
    meta:
        type = "privacy"
        category = "Device Information"
        file_type = "Android"
        weight = "0.250"
		//Allows an application to retrieve subscriber ID or IMSI

    strings:
        $subscriber_id = ".getSubscriberId" ascii nocase

    condition:
        $subscriber_id
}

rule device_info_sim_serialnumber : app_assist 
{
    meta:
        type = "privacy"
        category = "Device Information"
        file_type = "Android"
        weight = "0.250"
		//Allows an application to retrieve sim card serial number

    strings:
        $simsnum = ".getSimSerialNumber" nocase        

    condition:
        $simsnum
}

rule device_info_phone_number : app_assist 
{
    meta:
        type = "privacy"
        category = "Device Information"
        file_type = "Android"
        weight = "1.000"
		//Allows an application to retrieve phone number		

    strings:
        $phonenum = ".getLine1Number" nocase

    condition:
        $phonenum
}

rule browser_history : app_assist 
{
    meta:
        type = "privacy"
        category = "Device Information"
        file_type = "Android"
        weight = "0.250"
		//Allows an application to read the user's browser history and bookmarks.

    strings:
        $string1 = "getBrowserHistoryId" nocase
        $string2 = "getUrlVisits" nocase
        $field1 = "HISTORY_PROJECTION_TITLE_INDEX" nocase
        $field2 = "HISTORY_PROJECTION_URL_INDEX" nocase

    condition:
        1 of ($string*) or 1 of ($field*)
}

rule copy_shortcuts : app_assist 
{
    meta:
        type = "privacy"
        category = "Device Information"
        file_type = "Android"
        weight = "0.200"
		//Allows an application to copy shortcuts

    strings:
        $copy_shortcuts1 = /shortcut(.*\R){1,10}.*clone()/ nocase
        $copy_shortcuts2 = /clone()(.*\R){1,10}.*shortcut/ nocase
		
    condition:
        any of them
}

rule copy_bookmarks : app_assist 
{
    meta:
        type = "privacy"
        category = "Device Information"
        file_type = "Android"
        weight = "0.200"
		//Allows an application to copy browser bookmarks

    strings:
        $copy_shortcuts1 = /bookmark(.*\R){1,10}.*clone()/ nocase
        $copy_shortcuts2 = /clone()(.*\R){1,10}.*bookmark/ nocase

    condition:
        any of them
}

rule logcat_information : app_assist
{
    meta:
        type = "privacy"
        category = "Access Logs"
        file_type = "Android"
        weight = "0.250"	
		//Allows an application to read logcat information

    strings:
        $log1 = /logcat(.*\R){1,20}.*Runtime;\.exec/ nocase

    condition:
        $log1
}

rule sms_permission_read : app_assist 
{
    meta:
        type = "privacy"
        category = "Access Messages"
        file_type = "Android"
        weight = "1.000"
		//Allows an application to read sms

    strings:
        $perm5 = "android.permission.READ_SMS" nocase
        
    condition:
        $perm5
}

rule contacts_permissions : app_assist  
{
    meta:
        type = "privacy"
        category = "Access Contacts"
        file_type = "Android"
        weight = "1.000"
		//Allows an application to read contacts

    strings:
        $perm1 = "android.permission.READ_CONTACTS" nocase        

    condition:
        $perm1
}

rule record_microphone : app_assist  
{
    meta:
        type = "privacy"
        category = "Access Microphone"
        file_type = "Android"
        weight = "1.000"
		//Allows an application to use device microphone for recording

    strings:
        $perm1 = "android.media.AudioRecord" nocase

    condition:
        $perm1
}

rule camera_permission : app_assist  
{
    meta:
        type = "privacy"
        category = "Access Camera"
        file_type = "Android"
        weight = "1.000"
		//Allows an application to use device camera

    strings:
        $perm1 = "android.permission.CAMERA" nocase

    condition:
        $perm1
}

rule calendar_access : app_assist  
{
    meta:
        type = "privacy"
        category = "Access Calendar"
        file_type = "Android"
        weight = "1.000"
		//Allows an application to read calendar event informations

    strings:
        $code1 = "CalendarContract" nocase

    condition:
        $code1
}

rule location_permissions : app_assist 
{
    meta:
        type = "privacy"
        category = "Location"
        file_type = "Android"
        weight = "0.250"
		//Allows an application to access device location

    strings:
        $perm1 = "android.permission.ACCESS_COARSE_LOCATION" nocase
        $perm2 = "android.permission.ACCESS_FINE_LOCATION" nocase
        $perm3 = "android.permission.ACCESS_LOCATION_EXTRA_COMMANDS" nocase
        $perm4 = "android.permission.INSTALL_LOCATION_PROVIDER" nocase

    condition:
        1 of them
}

rule sms_mms_permissions_send : app_assist axmlprinter2
{
    meta:
        type = "privacy"
        category = "Access Messages"
        file_type = "Android"
        weight = "1.000"
		//Allows an application to send SMS and MMS

    strings:
        $perm1 = "android.permission.SEND_SMS" nocase
        $perm2 = "android.permission.SEND_MMS" nocase
        
    condition:
        1 of them
}

rule sms_mms_permissions_receive : app_assist axmlprinter2
{
    meta:
        type = "privacy"
        category = "Access Messages"
        file_type = "Android"
        weight = "1.000"
		//Allows an application to read SMS and MMS

    strings:
        $perm1 = "android.permission.RECEIVE_SMS" nocase
        $code2 = "android.permission.RECEIVE_MMS" nocase
        
    condition:
        1 of them
}

rule access_location : app_assist
{
    meta:
        type = "privacy"
        category = "Access Location"
        file_type = "Android"
        weight = "0.750"
		//Allows the application an access to the user's current location

    strings:
        $string1 = "Landroid/location/LocationManager;" 
        $string2 = ".getCellLocation" 
		$string3 = "Landroid/location/ILocationManager$Stub$Proxy;" 
		$string4 = "Landroid/webkit/WebChromeClient;.onGeolocationPermissionsShowPrompt"
		$string5 = "Landroid/webkit/GeolocationService;"
        
    condition:
        any of them
}

rule change_wifi_state : app_assist
{
    meta:
        type = "privacy"
        category = "Access Wifi"
        file_type = "Android"
        weight = "0.500"
		//Allows the application to connect to and disconnect from Wi-Fi access points and to make changes to configured Wi-Fi networks.

    strings:
        $string1 = "Landroid/net/wifi/IWifiManager$Stub$Proxy;" 
        $string2 = "Landroid/net/wifi/WifiManager" 				
        
    condition:
        any of them
}

rule control_nfc : app_assist
{
    meta:
        type = "privacy"
        category = "Access NFC"
        file_type = "Android"
        weight = "2.500"
		//Allows an application to communicate with Near-Field Communication

    strings:
        $string1 = "Landroid/nfc/tech"         
        
    condition:
        any of them
}


rule clear_cache : app_assist
{
    meta:
        type = "privacy"
        category = "Access Cache"
        file_type = "Android"
        weight = "0.500"
		//Allows the application to free phone storage by deleting files in application's cache directory.

    strings:
        $string1 = /Landroid\/content\/.*\;\.freeStorage/		
        
    condition:
        any of them
}


rule authenticate_accounts : app_assist
{
    meta:
        type = "privacy"
        category = "Access Accounts"
        file_type = "Android"
        weight = "2.000"
		//Allows an application to use the account authenticator capabilities of the Account Manager such as creating accounts as well as obtaining and setting their passwords.

    strings:
        $string1 = "Landroid/accounts/AccountManager"
		$string2 = "Landroid/accounts/IAccountManager$Stub$Proxy;"
        
    condition:
        any of them
}

rule change_wifi_multicaststate : app_assist
{
    meta:
        type = "privacy"
        category = "Access Wifi"
        file_type = "Android"
        weight = "0.500"
		//Allows the application to receive packets not directly addressed to your device. This can be useful when discovering services offered nearby.
		
    strings:
        $string1 = "Landroid/net/wifi/IWifiManager$Stub$Proxy;"
		$string2 = "Landroid/net/wifi/WifiManager$MulticastLock;"
		$string3 = "Landroid/net/wifi/WifiManager;.initializeMulticastFiltering"
		
        
    condition:
        any of them
}

rule record_audio : app_assist
{
    meta:
        type = "privacy"
        category = "Access Audio"
        file_type = "Android"
        weight = "0.500"
		//Allows the application to access the audio record path

    strings:
        $string1 = "Landroid/net/sip/SipAudioCall;.startAudio"
		$string2 = "Landroid/media/MediaRecorder;.setAudioSource"
		$string3 = "Landroid/media/AudioRecord;"
		$string4 = /Landroid\/speech\/SpeechRecognizer\;\.st.*Listening/
        
    condition:
        any of them
}

rule process_outgoing_calls : app_assist
{
    meta:
        type = "privacy"
        category = "Access Calls"
        file_type = "Android"
        weight = "1.000"
		//Allows the application to intercept outgoing calls

    strings:
        $string1 = /\"ACTION_NEW_OUTGOING_CALL\"/
        
    condition:
        any of them
}



rule read_phone_state : app_assist
{
    meta:
        type = "privacy"
        category = "Device Information"
        file_type = "Android"
        weight = "0.500"
		//Access the phone features of the device. It may determine the phone number and serial number of this phone.

    strings:
        $string1 = "Lcom/android/internal/telephony/IPhoneSubInfo$Stub$Proxy;.get"
		$string2 = "Lcom/android/internal/telephony/ITelephony$Stub$Proxy;.call"
		$string3 = "Landroid/telephony/TelephonyManager;.get"
        
    condition:
        any of them
}


rule access_sms : app_assist
{
    meta:
        type = "privacy"
        category = "Access Messages"
        file_type = "Android"
        weight = "1.000"
		//Allows application to access SMS or MMS messages stored on your phone or SIM card.

    strings:
        $ = "Landroid/provider/Telephony$Sms;.query"
		$ = "Landroid/provider/Telephony$Sms$Sent;.addMessage"
		$ = "Landroid/provider/Telephony$Sms$Draft;.addMessage"
		$ = "Landroid/provider/Telephony$Mms;.query"
		$ = "Landroid/provider/Telephony$Sms$Inbox;.addMessage"
		$ = /Landroid\/telephony\/.ms/

        
    condition:
        any of them
}

rule read_history_bookmarks : app_assist
{
    meta:
        type = "privacy"
        category = "Access Bookmarks"
        file_type = "Android"
        weight = "0.500"
		//Allows the application to read all the URLs that the browser has visited and browser's bookmarks.

    strings:
        $string1 = "Landroid/provider/Browser;"		
        
    condition:
        any of them
}


rule access_download_manager : app_assist
{
    meta:
        type = "privacy"
        category = "Access Download Manager"
        file_type = "Android"
        weight = "0.500"
		//Allows the application to access the download manager and may query the downloads that have been requested.

    strings:
        $string1 = "Landroid/app/DownloadManager;"		
        
    condition:
        any of them
}




rule get_tasks : app_assist
{
    meta:
        type = "privacy"
        category = "Access Task"
        file_type = "Android"
        weight = "0.500"
		//Allows application to retrieve information about currently and recently running tasks. May allow malicious applications to discover private information about other applications

    strings:
        $string1 = "Landroid/app/ActivityManager;.getRecentTasks"
		$string2 = "Landroid/app/ActivityManager;.getRunningTasks"

        
    condition:
        any of them
}







