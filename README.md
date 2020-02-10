# Detecting Process Injection Techniques:
This is a repository that is meant to hold detections for various process injection techniques.

# General Information: 

* Data analytics written within Jupyter Notebooks can be found within the `Detection_Notebooks` folder. 

* Datasets of each technique can be found within the respective folders. 

## Technqiues Covered Within This Project:
* DLL Injection
* Reflective DLL Injection
* Process Hollowing
* Process Reimaging (not necessarily injection, but still useful)
* Hook Injection via SetWindowsHookEx

## Resources: 
POC's:
* https://github.com/theevilbit/injection
* https://github.com/secrary/InjectProc
* https://github.com/djhohnstein/ProcessReimaging

# Reading From The Datasets: 

- You can read from the json file directly from within the notebooks (see Raw notebooks for an example). 

- You can ingest the datasets into your ELK stack by utilziing `kafkacat`.  Follow these steps: 

    *   Untar the dataset of choice:


            tar -xzvf dataset.tar.gz


    -  Use kafkacat to send dataset to Kafka broker:


            kafkacat -b <HELK IP>:9092 -t winlogbeat -P -l dataset.json



# Injection Information: 
* https://www.endgame.com/blog/technical-blog/ten-process-injection-techniques-technical-survey-common-and-trending-process
* https://warroom.rsmus.com/dll-injection-part-1-setwindowshookex/

# Authors:
* [Josh Prager](https://twitter.com/Praga_Prag)

* [Jonathan Johnson](https://twitter.com/jsecurity101)

* [David Polojac](https://twitter.com/@poloh4ck)
