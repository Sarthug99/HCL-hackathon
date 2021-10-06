Project - Malware Detection (Challenge Round 1)
Team - Gamebois
Members - Sarthak Umarani, Umang Sakhare, Ved Dandekar

LIBRARIES USED
    # For preprocessing
        - os
        - glob
        - statistics
        - json
	- sys
    # For visualization
        - matplotlib
    # For training and testing
        - sklearn
        - numpy
        - time
    # For exporting
        - pickle
	- csv

DIRECTORY STRUCTURE
    .
    ├── Analysis
    │   ├── Analyze_Dynamic_Data.ipynb
    │   ├── Analyze_Dynamic_Data.pdf
    │   ├── Analyze_Static_Data.ipynb
    │   └── Analyze_Static_Data.pdf
    ├── Training
    │   ├── train_dynamic.py
    │   └── train_static.py
    ├── Result
    │   ├── MalwareDetection.py
    │   └── models
    │       ├── dynamic_model
    │       └── static_model
    ├── README.txt

    4 directories, 10 files

    1. Analysis
        Contains the flow of the code along with it's explanation. Each stage of development and how we approached the problem statement
        has been described in the jupyter notebooks.
        Feature extraction, selection, training and testing have all been covered in the notebooks.
        Note: PDFs of both the notebooks have also been provided.
    
    2. Training
        Contains the code (.py files) to perform training. Their working has been explained in great detail in Analysis section.
        Usage
            train_dynamic.py: $python train_dynamic.py [malware_dir] [benign_dir]
            train_static.py: $python train_static.py [malware_dir] [benign_dir]

    3. Result
        Contains the resultant models along with the code to use them. 
        The program takes as input the full path to a directory containing static and dynamic analysis information.
        Usage
            MalwareDetection.py: $python MalwareDetection.py [directory]
	Note: After execution, a CSV file named "Predictions.csv" will be generated with two columns - Name and Prediction.

STATISTICS
    Dynamic Model:
        Model: Random Forest Classifier
        Accuracy: 0.9967811158798283
        Precision:  0.9923780487804879
        Recall:  0.9984662576687117
        F-score:  0.9954128440366974
        Testing time: 0.027327775955200195 seconds for 1864 predictions

    Static Model:
        Model: Random Forest Classifier
        Accuracy: 0.97
        Precision:  0.9669811320754716
        Recall:  0.9738717339667459
        F-score:  0.9704142011834319
        Testing time: 0.032489776611328125 seconds for 2500 predictions