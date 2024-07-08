# Mini-For-Facebook-App-Testing - Tania Jaswal

**DISCLAIMER: For Better Readability, Please Download The PDF** 

## Overview
The penetration testing of Mini for Facebook was conducted within the Android environment to comprehensively assess its security posture. Utilizing methodologies outlined in the OWASP Mobile Application Security Verification Standard (MASVS), our analysis aimed to identify vulnerabilities that could compromise user data and overall system integrity. The findings presented in this report offer a detailed examination of Mini for Facebook's security across various categories, revealing both strengths and weaknesses in its security measures. These insights provide valuable guidance for enhancing user privacy and data protection within the application.


## What is Mini for Facebook?
Mini for Facebook is a lightweight mobile application designed to provide users with a streamlined and efficient way to access the Facebook platform on their mobile devices. Developed as a companion app to the full-fledged Facebook application, Mini for Facebook offers essential features for browsing the social media platform while consuming minimal system resources and data bandwidth.
The app is optimized for performance, offering a simplified user interface that prioritizes essential functionalities such as news feed browsing, posting updates, messaging, and interacting with friends' content. Mini for Facebook aims to deliver a fast and responsive user experience, catering to users who seek a lightweight alternative to the resource-intensive official Facebook app.


## Why OWASP Testing?
OWASP provides a standardized framework for evaluating the security of web applications, including mobile apps. By subjecting Mini for Facebook to OWASP testing, we aim to achieve several objectives:
Identifying Vulnerabilities: OWASP testing helps uncover security vulnerabilities or weaknesses present in the Mini for Facebook app. This includes vulnerabilities related to data storage, cryptography, authentication, network communication, platform interaction, code quality, and resilience requirements.
Mitigating Risks: By identifying vulnerabilities early, we can proactively mitigate security risks associated with Mini for Facebook. This involves implementing necessary security controls, patches, and fixes to address identified vulnerabilities and strengthen the overall security posture of the application.
Protecting User Data: Mini for Facebook likely handles sensitive user data, including personal information, login credentials, and communication data. Ensuring the security of this data is crucial to protecting user privacy and preventing data breaches. OWASP testing helps identify and address vulnerabilities that could compromise the confidentiality, integrity, or availability of user data.
Enhancing Trust and Confidence: A secure application fosters trust and confidence among users, demonstrating a commitment to protecting their privacy and security. By subjecting Mini for Facebook to rigorous security testing and implementing necessary security measures, we can instill trust in users and reassure them that their data is being handled securely.
Compliance Requirements: Compliance with industry regulations and standards is essential for organizations handling user data. OWASP testing helps ensure that Mini for Facebook complies with relevant security standards and regulations, reducing the risk of non-compliance penalties and legal repercussions.



## Overview of OWASP Testing
OWASP (Open Web Application Security Project) testing refers to a comprehensive assessment of web applications to identify and mitigate potential security vulnerabilities. The OWASP project provides a standardized methodology and checklist for evaluating the security posture of web applications, ensuring they adhere to best practices and guidelines for secure development.
The testing process involves examining various aspects of the web application, including its storage mechanisms, cryptography implementations, authentication mechanisms, network communication protocols, platform interactions, code quality, build settings, and resilience to common security threats. Each aspect is evaluated against the requirements outlined in the OWASP Mobile Application Security Verification Standard (MASVS), which provides a set of criteria for assessing the security of mobile applications.

**The key components of OWASP testing:**
**1. Storage Testing:** Evaluates how the application handles sensitive data storage, including proper encryption, secure storage mechanisms, and protection against unauthorized access.
**2. Cryptography Testing:** Assesses the implementation of cryptographic algorithms and protocols within the application to ensure the confidentiality, integrity, and authenticity of data.
**3. Authentication Testing:** Verifies the effectiveness of the application's authentication mechanisms in preventing unauthorized access to sensitive resources and user accounts.
**4. Network Communication Testing:** Examines the security of network communication protocols used by the application to transmit data, ensuring encryption, integrity protection, and protection against common network-based attacks.
**5. Platform Interaction Testing:** Reviews how the application interacts with the underlying mobile platform, including permissions, data sharing, and integration with device features such as GPS, camera, and contacts.
**6. Code Quality and Build Settings Testing:** Analyzes the source code of the application for security vulnerabilities, coding errors, and misconfigurations, as well as ensuring secure build settings to prevent potential exploitation.
**7. Resilience Requirements Testing:** Tests the application's resilience to common security threats such as injection attacks, cross-site scripting (XSS), cross-site request forgery (CSRF), and insecure direct object references (IDOR).
**8. App Privacy Testing:** App privacy testing assesses how the application collects, uses, and protects user data, ensuring compliance with privacy regulations and best practices. It involves evaluating privacy policies, data collection practices, user controls, and security measures to safeguard user privacy and prevent unauthorized access or misuse of personal information.


## MASVS Storage Testing

**MASVS-STORAGE-1**

MASVS-STORAGE-1 stipulates that the app securely stores sensitive data, protecting against unauthorized access or tampering. This criterion underscores the need for robust security measures to maintain the confidentiality and integrity of user information, both locally and remotely. The app demonstrates a commitment to data security and user privacy by complying with this standard.

**Testing Conducted for the Storage Testing:**

These are the internal and external local storage created by the application-

Shared_prefs- This directory is used to store application preference information in Android ASCII or binary XML files.
Files- The files directory is used by the app to store arbitrary file data used for the application.
Cache- This temporary storage location is used by the app within the sandbox.
Databases- This is used for storage of most local app data in SQLite databases.


**Findings under Cache directory-**
The cache directory of the app reveals a typical structure with WebView, afwad, and picasso-cache folders. The Picasso-cache folder stores HTTP responses, suggesting the caching of fetched URLs, while the WebView folder seems to contain various cache data related to the web view, including crash reports, safe browsing data, and font information. 


**Findings under Database directory-**
The examination of SQLite databases extracted from "Gold_Finger.V.X.your_Facebook" reveals a structured schema comprising tables like alarms, composite_measurement_sessions, measurements, reports, routines, sending, and speed. Each table appears to house diverse datasets, encompassing alarm configurations, composite measurement sessions, network measurements, sentiment analysis reports, event routines, sending-related activities, and speed measurements. However, due to the app's non-debuggable nature, extraction into a SQLite database viewer is unfeasible. Despite this, no sensitive information appears to be stored within the tables. It's noteworthy that the SQLite database lacks encryption, as evidenced by its accessibility through cat commands.


**Findings for Files Directory-**
A realm database named "default" was identified within the application. However, due to the app's non-debuggable nature, extraction of the files for inspection in the realm browser was not possible.


**Finding for Shared_prefs-**
Shared Preferences are inherently insecure and lack encryption by default. Our examination revealed several instances of sensitive information within files like CookieSave.xml, Preference.xml, APPFIREWORKS.xml, and oscontribution.xml. These files contain data such as session cookies, SID, device location details, and SD contents, which could potentially be exploited if accessed by unauthorized parties.


## Permissions of the files in /data/data/com.Gold_Finger.V.X.your_Facebook-

**To know the permissions better-**

– User: This is the owner of a file and the owner of the file belongs to this class.
– Group: The members of the file’s group belong to this class
– Other: Any users that are not part of the user or group classes belong to this class.

Most directories, such as app_textures, cache, databases, files, and shared_prefs, have read, write, and execute permissions for both the owner (u0_a176) and the group (u0_a176). However, app_webview has these permissions exclusively for the owner. Additionally, the cache directory has a special setuid/setgid permission. 


**Conclusion for MASVS-STORAGE-1-**
In conclusion, the app fails to securely store sensitive information, as evidenced by the presence of unprotected data in various storage locations. This non-compliance with MASVS-STORAGE-1 indicates a potential vulnerability in the app's data storage practices.

## MASVS-STORAGE-2
MASVS-STORAGE-2 entails ensuring that the app effectively prevents any sensitive data from leaking or being exposed to unauthorized access.

Conducted Testing:

Testing Backups for Sensitive Data-

AllowBackup-


The 'AllowBackup' setting is configured to 'true,' enabling the application to generate backups, potentially leading to the inadvertent storage and exposure of sensitive data. Consequently, the application does not meet the required standards and fails this evaluation.

Shared preferences-


Shared preferences encompass files susceptible to cloud backup. Upon scrutiny, it's evident that CookieSave.xml and Preference.xml harbor sensitive user information, such as session cookies and SD contents. These data elements are vulnerable to exploitation, paving the way for session hijacking and data leakage. Though not all entries may be equally sensitive, items like session cookies in CookieSave.xml, SID in APPFIREWORKS.xml, and device location details in oscontribution.xml, present tangible security risks if compromised or exploited. The application falls short in this evaluation.
 

Determining Whether the Keyboard Cache Is Disabled for Text Input Fields-
While the application provides search suggestions akin to Facebook's functionality, it notably lacks suggestions in other areas. Additionally, it's observed that the keyboard cache remains enabled for certain input fields. Despite this, considering that only people's names are suggested, which typically aren't deemed sensitive unless coupled with additional data, it could be argued that the application successfully meets the test criteria. Moreover, there was no keyboard cache identified within the cache directory. Thus, the application is deemed compliant with this evaluation.



Determining Whether Sensitive Data is Sent to Third Parties by Embedded Services-
During communication testing, it was observed that the application interacted with Facebook, which is expected given its origin as a derivative of Facebook. However, in our recent investigation, no data pertinent to Facebook, such as user IDs, was identified as being transmitted to or from the app. Therefore, based on these findings, the application successfully passes this test.



**Conclusion for MASVS-STORAGE-2-**
The application demonstrates vulnerabilities in preventing the leakage of sensitive data. Notably, the allowance for backups introduces the potential for sensitive information to be stored insecurely. Additionally, an examination of shared preferences reveals XML files housing sensitive data, posing exploitable risks. These findings highlight areas where the application's data protection measures fall short, necessitating immediate attention and remediation to mitigate potential security breaches and safeguard user information effectively.



**Extra MASVS-STORAGE Testing**

Log Testing-



In the log testing of the app, it was observed that despite logging in and utilizing various app functionalities, no sensitive information was found in the logs.

Memory Testing-

During memory testing, attempts to dump the memory and extract a Txt file were unsuccessful. Despite the app being operational during testing, fridump failed to connect to it. However, the process IP of the app was successfully identified.



**Conclusion for Log and Memory Testing-**
In conducting both log and memory testing on the application, it was observed that while log testing revealed no instances of sensitive information exposure within the application's logs, memory testing encountered difficulties. Despite efforts to dump the memory and extract data using Fridump, the tool failed to establish a connection with the running application. Although the process ID of the application was identified, Fridump was unable to interact with it successfully. 



## MASVS Cryptography

**MASVS-CRYPTO-1**

MASVS-CRYPTO-1 assesses if the app employs up-to-date and robust encryption methods in line with industry standards. It ensures sensitive data, like user credentials, remains well-protected against modern cyber threats, enhancing overall security and reducing the risk of unauthorized access or tampering.

Testing Conducted for Cryptography Testing:

The MobSF report indicates that the app utilizes inadequate random number generators, a critical security flaw. This finding highlights a significant vulnerability in the app's cryptographic implementation, potentially exposing sensitive data to exploitation by attackers. Therefore, the app does not meet the requirements for robust cryptographic practices.



The app's utilization of MD5 and SHA-1 cryptographic algorithms signifies a concerning lapse in security measures. Both MD5 and SHA-1 are widely recognized as outdated and vulnerable to exploitation by attackers, rendering them unsuitable for robust data protection. By employing these weak algorithms, the app exposes user data to significant risks, contravening industry best practices for cryptographic security. Consequently, the app fails to meet the requisite standards for secure cryptographic implementation.




The application effectively meets the criteria for hard-coded secrets, as the ones highlighted in the MobSF report were unrelated to the app's functionalities. Additionally, no passwords were discovered within the assets, ensuring compliance with security standards in this regard.




The absence of AES and DES encryption relevant to the application ensures compliance, indicating that the app successfully passes this test.


**Conclusion for MASVS Cryptography:**
In conclusion, the cryptography testing of the app identified several critical vulnerabilities in its encryption practices, highlighting areas of concern for data security. The app's reliance on inadequate random number generators and the use of weak cryptographic algorithms such as MD5 and SHA-1 pose significant risks to user data, potentially exposing it to exploitation by malicious actors. While the app demonstrates satisfactory handling of hard-coded secrets and does not employ vulnerable encryption methods like AES and DES, the identified vulnerabilities overshadow these strengths. Moving forward, addressing these cryptographic weaknesses is imperative to enhance the overall security posture of the app and mitigate the risk of unauthorized access or data tampering. By adopting up-to-date encryption methods and implementing robust cryptographic practices, the app can better protect sensitive user data and ensure compliance with industry standards for secure data handling.




## MASVS Authentication
**MASVS-AUTH-1**

Testing Methods Conducted for Authentication Testing:

Endpoint URLs-

The MobSF report did not include URLs in the PDF report, but they were accessible in the original report. According to the findings, the app predominantly utilizes URLs that necessitate authentication, such as those for Google, Facebook, Instagram, and YouTube. Based on this assessment, the app successfully passed the test.




Since this app serves as a mini version of Facebook, it's apparent that authentication is directed to Facebook servers, as observed in prior testing phases. However, it's unclear whether local authentication mechanisms are entirely absent. Therefore, the testing outcome remains inconclusive.




Strong Password Policy-
The app imposes no additional constraints on passwords beyond a minimum length of six characters. Therefore, it meets the criteria for a strong password policy, and the test is considered passed.




The app fails the test as it allows unlimited attempts on passwords without any prevention, limits, or blocking mechanisms. However, an alternative login method via SMS to the phone number is provided by the app.


The app passed the test as there were no relevant instances of "token" or JWT found in the code, and none of the hardcoded secrets were related to the app. Therefore, no hidden tokens were discovered in the code.



The app fails the test due to its lack of session timeout functionality, which leaves user sessions vulnerable to exploitation. This could potentially lead to unauthorized access to user accounts if a device is left unattended with an active session. Implementing session timeout measures is crucial for enhancing overall security and protecting user data from unauthorized access.



The app successfully passes the test as it requires users to log in again after logging out, even when attempting to return using the back button. This indicates that the auto-login feature is disabled upon logout, enhancing security by preventing unauthorized access to user accounts.



The app successfully passes this test as it provides users with the functionality to block or report other individuals, similar to the features available on the Facebook platform. This capability enhances user control over their interactions within the app, contributing to a safer and more secure user experience.




**MASVS-AUTH-2**

MASVS-AUTH-2 assesses whether the app securely implements local authentication in accordance with platform best practices. This involves ensuring that the app follows established guidelines and standards for handling authentication processes locally on the device. Key considerations include securely storing and managing authentication credentials, implementing secure login mechanisms, and protecting user data from unauthorized access. In essence, MASVS-AUTH-2 evaluates whether the app adheres to platform-specific security recommendations to safeguard user authentication within the application.

Testing Methods Used:

While the app primarily relies on external authentication services, such as Facebook, it does offer users the option to enhance security through local authentication by setting up a PIN within the app. This feature allows users to add an extra layer of protection to their accounts, providing greater control over access to their personal information and interactions within the app.






**MASVS-AUTH-3**

MASVS-AUTH-3 requires apps to implement additional authentication measures for sensitive operations, such as making financial transactions or changing critical settings. This ensures that even if a user's session is compromised, unauthorized access to sensitive functionalities is prevented. In essence, it adds an extra layer of security to safeguard against potential misuse or unauthorized access to critical app functionalities.

The app only utilizes SMS verification when users forget their passwords; however, it lacks multi-factor authentication (MFA) beyond this scenario. As MFA is a crucial security measure for protecting user accounts, its absence renders the app non-compliant with this test.



Conclusion for MASVS Authentication:
In conclusion, the authentication testing of the app revealed both strengths and weaknesses in its implementation of authentication mechanisms. While the app effectively utilizes external authentication services for user login, such as those provided by Facebook, it lacks robust local authentication mechanisms. The absence of password complexity requirements and limitations on login attempts poses security risks, albeit mitigated to some extent by the availability of alternative login methods like SMS verification. Additionally, the app fails to implement session timeout functionality, leaving user sessions vulnerable to exploitation. However, it demonstrates adequate measures for user account management, including options to block or report other users. Moving forward, addressing these authentication vulnerabilities and implementing additional security measures, such as robust password policies and session management controls, is crucial for enhancing the overall security posture of the app and safeguarding user data.



## MASVS Network Communication

**MASVS-NETWORK-1**
​​MASVS-NETWORK-1 evaluates how securely an app communicates over networks. It assesses whether the app uses secure communication protocols to transmit data, ensuring confidentiality, integrity, and authenticity. Essentially, this test examines whether the app employs encryption and secure transmission mechanisms to protect user data from eavesdropping, tampering, and unauthorized access while in transit over networks.

Testing Conducted for ​​MASVS-NETWORK-1:

The Wi-Fi traffic analysis, conducted using Wireshark to scrutinize all app functions such as login and account viewing, successfully passed the testing. Through meticulous filtering, no unencrypted HTTP usage was detected, affirming robust encryption practices. TLS, including versions 1.2 and 1.3, was identified, ensuring secure data transmission. No clear-text credentials were observed during the Wireshark analysis. The data was encrypted by TLS protocol. Overall, the findings confirm the efficacy of the encryption measures, thus indicating a passing result for the analysis.





Capture HTTPS Traffic with Burp Suite-

   The app did not work properly with the proxy because the app uses SSL Pinning which blocks the proxy, we will use Frida to solve this issue.



Investigated SSL pinning using Frida:

SSL pinning was implemented on the app, so bypassing was necessary. Bypassed using Frida tool. After bypassing, the traffic of the Facebook app was captured. The traffic shows that the app uses HTTP/2 which supports encryption through the use of Transport Layer Security (TLS), which is also used by the app. There were no findings of clear text seen in the traffic. The app also uses cookies to store the user information. 



**MASVS-NETWORK-2**
MASVS-NETWORK-2 mandates encrypting data in transit to secure sensitive information exchanged between mobile apps and servers, mitigating interception risks and ensuring compliance with industry standards.

MobSF did detect the SSL certificate pinning mechanisms in the app. The app passes this test.




**Conclusion for MASVS NETWORK :**

The final project app demonstrates a robust communication protocol, adhering to MASVS standards for network security. No plaintext traffic or clear text credentials were observed during testing. The app uses TLS supported by HTTP/2, ensuring secure communication with the server. Additionally, certificate pinning mechanisms were detected as the app uses SSL pinning to detect attacks. Overall, the app's communication architecture meets security best practices and ensures the confidentiality and integrity of user data during transmission. 


## MASVS Platform Interaction

**MASVS-PLATFORM-1**

MASVS-PLATFORM-1 necessitates the secure implementation of Inter-Process Communication (IPC) mechanisms within the mobile application, ensuring that communication between different processes or components is protected against unauthorized access, data leakage, or manipulation. Compliance involves practices such as implementing proper access controls, encrypting sensitive data, using secure communication channels, and validating input to prevent exploitation vulnerabilities, thus maintaining the integrity and confidentiality of inter-process communication and aligning with best practices for secure application development.

Testing Conducted for MASVS-PLATFORM-1:

Testing for App Permissions-
These are the app permissions that the app uses-


In evaluating app permissions, several potentially risky permissions were identified, including ACCESS_LOCATION, ACCESS_COARSE_LOCATION, ACCESS_FINE_LOCATION, CAMERA, WRITE_EXTERNAL_STORAGE, and READ_EXTERNAL_STORAGE. According to the Mobsf report, there are indications that the app might be misusing these permissions, raising concerns about potential abuse. Consequently, based on these findings, the test results are deemed unsuccessful.

Testing Deep Links-
The test for deep links yielded no discoveries within the app, as no deep links were detected in the XML file, indicating a lack of data elements associated with intents. Based on this outcome, it can be concluded that the test was successful.

Testing for Sensitive Functionality Exposure Through IPC-
The test aimed at uncovering sensitive functionality exposure through Inter-Process Communication (IPC) highlighted that none of the activities were exported except for the service elements. However, the only activity with an intent filter was identified as com.Gold_Finger.p037V.p038X.your_Facebook.MainActivity serves as the main activity for the app. The test passes.


Determining Whether Sensitive Stored Data Has Been Exposed via IPC Mechanisms-
The assessment aimed at determining whether sensitive stored data had been exposed via Inter-Process Communication (IPC) mechanisms revealed that the app lacked any associated content providers. As a result, the test is considered successful, indicating that sensitive stored data has not been exposed via IPC mechanisms.


**MASVS-PLATFORM-2**
MASVS-PLATFORM-2 requires securely integrating and using WebViews in the mobile app to mitigate web-related security risks. Compliance involves implementing measures like input validation, output encoding, and Content Security Policy enforcement. This ensures consistent security across different app components using web content, enhancing overall security against malicious attacks.

Testing WebView Protocol Handlers-
After Checking for “android.webkit.WebView.EnableSafeBrowsing” in AndroidManifest.xlm, it is not present hence safe browsing is enabled. Tested how the Webview was handled in the app. This test passed since safe browsing is enabled.


Testing JavaScript Execution in WebViews-
The setJavaScriptEnabled is set to true in the application’s com file. The test failed as the javascript execution is set to true in the app.



**MASVS-PLATFORM-3**
Finding Sensitive Information in Auto-Generated Screenshots-


The FLAG_SECURE flag has not been set so the activity information is being shown. This test failed as we were able to find relevant information on the app and how it protects sensitive information.





Testing for Overlay Attacks-
This can not be tested on the app since it doesn’t have any content providers in the manifest. So, the test passes due to no content element. The app doesn’t use any of the onFilterTouchEventForSecurity, android:filterTouchesWhenObscured, and FLAG_WINDOW that could be used to overlay or override. This test passed since no information could be found.









Checking for Sensitive Data Disclosure Through the User Interface-





The app doesn’t use any hard-coded input type password which suggests that the passwords are handled correctly. The app uses the Notification Manager function to manage the notifications that are sent from the app. The app doesn’t disclose any sensitive data through any password leak. The use of sensitive data is completely removed. Hence, the test passes.

**Conclusion for MASVS PLATFORM:**
In summary, the testing conducted for MASVS-PLATFORM standards showcased a comprehensive assessment of various security aspects within the mobile application. While certain areas demonstrated successful compliance, such as the secure usage of WebViews, implementation of safe browsing, and absence of sensitive data disclosure through the user interface, other areas highlighted potential vulnerabilities. These include concerns regarding the misuse of app permissions, issues with JavaScript execution in WebViews, and exposure of sensitive information in auto-generated screenshots. However, positive outcomes were also observed, such as the absence of deep links and vulnerability to overlay attacks. Overall, the evaluation underscores a proactive approach to enhancing the application's security posture while identifying areas for further improvement to meet MASVS standards comprehensively.





## MASVS Code Quality and Build Settings
**MASVS-CODE-1**
MASVS-CODE-1 mandates that the mobile application necessitates an up-to-date platform version, emphasizing the importance of using the latest operating system and software updates. This requirement aims to mitigate security vulnerabilities by ensuring compatibility with the most recent security patches and enhancements, thereby enhancing the overall security posture of the application.

Check if the app runs on the unsupported Android version-
The app does run on the unsupported Android version 28. Hence, this test failed.




**MASVS-CODE-2**
In the testing process, an older version of the Mini for Facebook APK was downloaded, with two different options explored. Both downloads resulted in the same error message, indicating the utilization of an unsupported version, thereby hindering Facebook login. This test passes, demonstrating successful observation of the app's handling of older versions and its implementation of appropriate version compatibility checks.



**MASVS-CODE-3**
In the binary analysis section, no vulnerable libraries were identified in the Mobsf report. As a result, no conclusions could be drawn regarding potential vulnerabilities. This test passes, indicating that no concerning findings were detected during the analysis of the binary.



**MASVS-CODE-4**
Testing for URL Loading in WebViews-
The examination for URL loading in WebViews revealed the absence of "EnableSafeBrowsing" in the manifest file. As this feature was not detected, it can be inferred that safe browsing is enabled by default. Therefore, this test is considered successful, confirming the presence of safe browsing functionality within the application's WebViews.


Testing for Injection Flaws-
The assessment revealed no presence of deep links within the app, as confirmed by the absence of data elements in the XML file and no exported activities except for service elements. Furthermore, the main activity, com.Gold_Finger.p037V.p038X.your_Facebook.MainActivity, was identified without any intent filter. Additionally, due to the absence of content providers in the manifest and no utilization of overlay-related attributes, overlay attacks couldn't be tested but were implicitly passed. Moreover, the absence of signs of injection flaws led to the successful completion of the injection flaw test.

Conclusion for MASVS Code Quality and Build Settings:
In conclusion, the evaluation of MASVS Code Quality and Build Settings encompassed several tests assessing the application's adherence to secure coding practices and platform standards. While the app failed the compatibility test for running on unsupported Android version 28 (MASVS-CODE-1), it demonstrated successful handling of older versions during login (MASVS-CODE-2). The absence of vulnerable libraries in the binary analysis (MASVS-CODE-3) and secure URL loading in WebViews (MASVS-CODE-4) further reinforced its robust security posture. Overall, these findings highlight the app's commitment to maintaining code quality and adherence to industry standards.
MASVS Resilience Requirements
MASVS-RESILIENCE-1
MASVS-RESILIENCE-1 mandates that the app validates the integrity of the platform. This involves verifying the authenticity and integrity of the underlying operating system and platform components to ensure they have not been tampered with or compromised. This requirement aims to mitigate risks associated with unauthorized modifications or attacks targeting the app's underlying platform, thereby enhancing its resilience against potential security threats.



## MASVS-RESILIENCE-2

The app employs a valid APK signature utilizing SHA-256 with RSA. However, it relies on a v1 signature, which is insecure. The app fails the test since it uses an insecure APK signature. 



## MASVS-RESILIENCE-3

MASTG-TEST-0041
The app's use of strict mode suggests that it is implementing measures to enhance its resilience against certain types of errors or vulnerabilities. Strict mode is a programming feature that enforces stricter parsing and error handling, helping to identify potential issues and prevent them from causing system failures or security vulnerabilities. Therefore, the app's adoption of strict mode aligns with best practices for resilience and security. Overall, this aspect of the app can be considered a pass.















MASTG-TEST-0051-
The app contains unintelligible names for classes, methods, and variables, which makes it harder to understand the code hence obfuscating the meaning behind it. 
It dynamically fetches the encryption algorithm and key generation methods from encoded strings.





























MASVS-RESILIENCE-4

MASTG-TEST-0039-

The app is not debuggable since the debuggable is not set in AndroidManifest.xml. 

Other remarks:
The app requests a broad range of permissions, including access to sensitive device information (e.g., READ_PHONE_STATE), network access (INTERNET), camera access (CAMERA), and storage access (WRITE_EXTERNAL_STORAGE, READ_EXTERNAL_STORAGE). The extensive permission requests may raise privacy concerns.
The app incorporates third-party libraries for functionalities like ads, fingerprint authentication, and app tracking.









**Conclusion for MASVS RESILIENCE:**
In conclusion, the app exhibits varying degrees of resilience across the MASVS-RESILIENCE standards. While MASVS-RESILIENCE-1 demonstrates successful platform validation, as evidenced by its functionality on the emulator, concerns arise regarding its compatibility with rooted devices. On the other hand, MASVS-RESILIENCE-2 highlights the implementation of a standard APK signature mechanism, ensuring the integrity of the APK. Moreover, the app showcases resilience against static analysis through obfuscation techniques, as outlined in MASVS-RESILIENCE-3. However, it lacks robust anti-dynamic analysis measures, as evidenced by the absence of debuggable flags. Overall, while the app demonstrates resilience in some areas, further enhancements are warranted to bolster its overall security posture.

## Testing App Privacy
This testing assesses the privacy compliance of Mini for Facebook, a mobile application that provides a lightweight version of the Facebook platform. The evaluation is based on the Future Privacy Foundation Best Practices for Mobile App Developers and aims to identify areas of strength and improvement regarding user privacy protection.
**1. Communicate Openly and Effectively:**
Privacy Policy Review: The Mini for Facebook's privacy policy was evaluated for clarity and comprehensiveness. The policy effectively outlines data collection, sharing, and user practices using clear language understandable to the average user. It covers aspects such as what data is collected, how it's used, and users' rights. Since Mini for facebook is connected to the larger version of Facebook, it provides the same security and privacy guidelines as Facebook.


**2. Make Your Privacy Policy Easily Accessible:**
Prominence of Privacy Policy: The app prominently features a link to the privacy policy within the settings menu. This ensures that users are informed about data practices before engaging with the app.
Accessibility: Users can easily access the privacy policy from within the app, located in the settings menu. This accessibility ensures that users can reference the policy whenever they have privacy-related concerns.
Enhanced Notice: Mini for Facebook does not currently implement enhanced notice features, such as contextual pop-ups or notifications when accessing sensitive data.




**3. Use Enhanced Notice:**
Contextual Awareness: Mini for Facebook lacks enhanced notice features in situations where users might not expect certain data to be collected. For example, when accessing location data for check-ins or when enabling features that require access to the device's microphone or camera, the app does not provide contextual notifications or explanations regarding the data collection.







**4. Provide Users with Choices and Controls:**
Choice and Control Features: Mini for Facebook offers users various options to customize their privacy settings, including controlling who can see their posts, managing app permissions, and opting out of targeted advertising.
Customization: Users can tailor their privacy settings according to their preferences, empowering them to manage their data effectively. This includes options to adjust visibility settings for posts and profile information.




**5. Secure Your Users' Data:**
Security Measures: Mini for Facebook employs robust encryption protocols to protect user data, including end-to-end encryption for messages and secure HTTPS connections for data transmission. Additionally, the app uses secure authentication mechanisms to prevent unauthorized access to user accounts.





Data Handling: While the app is secure in sending the data, there are some aspects of data storage that were not handled in a secure way. After examining the information in xml files under shared preferences, we found that CookieSave.xml and Preference.xml contains sensitive user data, including session cookies and sd contents, which can be exploited for session hijacking and data leakage. While not all data may be sensitive, some entries, like session cookies in CookieSave.xml, SID in APPFIREWORKS.xml, and device location details in oscontribution.xml, could pose security risks if exposed or misused.




**Conclusion for Privacy Testing:**
In conclusion, while Mini for Facebook exhibits commendable efforts in certain aspects of privacy compliance, such as transparent communication of privacy policies and providing users with control over their data, it falls short in other critical areas. The absence of enhanced notice features, particularly in contexts where unexpected data collection occurs, poses a significant concern. Additionally, issues regarding the security of stored data, as evidenced by sensitive information found in XML files, raise questions about the app's overall privacy performance. Therefore, while it may not be accurate to categorically label the app as failing the privacy test, there are substantial areas requiring improvement to ensure enhanced privacy protection for users.







## Mini For Facebook Conclusion:

In evaluating Mini for Facebook's security and privacy posture, it's evident that while the app demonstrates strengths in certain areas, it also harbors vulnerabilities that lean it towards the less secure side. For instance, the presence of unprotected sensitive data in various storage locations, such as insecurely stored user preferences and cached data, highlights shortcomings in storage security practices. Additionally, the discovery of weak cryptographic algorithms like MD5 and SHA-1 being utilized for data encryption underscores critical flaws in cryptography practices, leaving user data susceptible to exploitation by malicious actors.
Moreover, deficiencies in authentication mechanisms, such as the absence of robust local authentication and session management controls, are particularly concerning. For example, the lack of password complexity requirements and session timeout functionality increases the risk of unauthorized access to user accounts. This was further accentuated during testing when it was observed that the app failed to implement session timeout functionality, leaving user sessions vulnerable to exploitation, potentially compromising user privacy and security.
Furthermore, issues regarding the security of stored data, such as sensitive information being found in XML files without proper encryption or access controls, raise significant red flags. For instance, during privacy testing, it was discovered that user profile information and preferences were stored in plain text XML files, leaving them susceptible to unauthorized access or extraction. These lapses in data security not only violate user privacy but also undermine user trust in the app's ability to protect their sensitive information effectively.
However, despite these vulnerabilities, Mini for Facebook has the opportunity to strengthen its security posture through proactive measures and comprehensive remediation efforts. For example, by implementing robust encryption algorithms like AES and enhancing authentication mechanisms with multifactor authentication and session management controls, the app can significantly mitigate security risks and enhance user data protection. Additionally, conducting regular security assessments and investing in employee training on security best practices can help cultivate a culture of security awareness within the organization, further bolstering its overall security posture and resilience against evolving threats.







