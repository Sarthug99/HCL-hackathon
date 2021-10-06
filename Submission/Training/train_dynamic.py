#!/usr/bin/env python
# coding: utf-8

# # Dynamic Data Analysis

# We begin by importing all the necessary libraries

# For preprocessing
import os
import sys
from glob import glob
import statistics
import json

# For training
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import numpy as np
import time

# For exporting
import pickle


# # Analysis

# We'll begin our analysis by making a list of all the files that are available to us for analysis

try:
    if(sys.argv[1] != None):
        if os.path.exists(sys.argv[1]):
            malware_dir = sys.argv[1]
        else:
            sys.exit("Please provide a valid malware directory.")
    else:
        sys.exit("usage: python train_dynamic.py malware_directory benign_directory")

    if(sys.argv[2] != None):
        if os.path.exists(sys.argv[2]):
            benign_dir = sys.argv[2]
        else:
            sys.exit("Please provide a valid benign directory.")
    else:
        sys.exit("usage: python train_dynamic.py malware_directory benign_directory")
except:
    sys.exit("usage: python train_dynamic.py malware_directory benign_directory")

malwares = []
benigns = []


# Extract and save path of each data point
for root, dirs, files in os.walk(benign_dir):
    for file in files:
        # Append file names to list
        benigns.append(os.path.join(root, file))

# Extract and save path of each data point
for root, dirs, files in os.walk(malware_dir):
    for file in files:
        # Append file names to list
        malwares.append(os.path.join(root, file))


# Now, lets have a look at our features to get a better understand of our data.

# In this case, we were able to get incredible results using just one feature - Severity.
#
# Severity is a measure (on a scale of 8) of how critical the code section that is being executed is.
#
# In general, malwares will try to access more critical code and thus attain a higher severity rate.


def max_severity(f_path):
    f = open(f_path, "r", errors="ignore", encoding="utf8")
    f = json.load(f)
    severities = [0]
    for each in f["signatures"]:
        severities.append(each["severity"])
    return max(severities)


# # Training

# We will use the function we defined above to extract features.
#
# For the sake of abstract and future use, we will create a wrapper function that for now, only calls that one function.


def extract_features(f_path):
    return [max_severity(f_path)]


# Next, we write the code to send files from our dataset for feature extraction


# Number of samples to take of each type. Set as a negative to use entire dataset
limit = -1

x = []
y = []

i = 0
for file in benigns:
    x.append(extract_features(file))
    y.append(0)
    i += 1
    if i == limit:
        break

i = 0
for file in malwares:
    x.append(extract_features(file))
    y.append(1)
    i += 1
    if i == limit:
        break

x = np.array(x)
y = np.array(y)

x_train, x_test, y_train, y_test = train_test_split(x, y,
                                                    test_size=0.25,
                                                    random_state=42)


# Now, onto the actual trainning.
#
# We use Random Forest Classifier as the data is highly threshold based. Forest classifiers give good results on such data.


clsf = RandomForestClassifier()
start = time.time()
clsf.fit(x_train, y_train)
stop = time.time()
print(f"Training time: {stop - start} seconds")


# # Testing

# Now that our model is trained, we can test it's accuracy and speed


start = time.time()
accuracy = str(clsf.score(x_test, y_test))
stop = time.time()
print("Accuracy: " + accuracy)
print(f"Testing time: {(stop - start)} seconds for {len(y_test)} predictions")


# Clearly, our model is able to give us incredible accuracy and speed with just one feature.
#
# This is the most ideal possible case for a ML algorithm.

# # Export

export_name = "dynamic_model"
pickle.dump(clsf, open(export_name, 'wb'))
print("Model saved as " + export_name)
