## A collection of different keylogger detection methods.

This was code used in my thesis/dissertation used to compare the effectiveness of different keylogger strategies:

1. Machine-Learning - Used a kaggle dataset of keylogger and benign data to predict the likelihood of a keylogger present on a machine
2. API-Hooking - Used Frida in Python to inject JavaScript into processes to check for malicious Windows-API calls
3. Network Analysis - Used tools such as Wireshark and CICFlowMeter to study malicious periodic network traffic
4. Signature-Detection - Used YARA rules to formulate a simple signature-based detection strategy.

It was evaluated that each method had their own individual weaknesses, and due to current nature of keylogger behaviour, it was documented that a hybrid approach would be more successful than any individual detection strategy. 

It should be noted that this was for research purposes only, and will not detect all existing current keyloggers. 
