#!/usr/bin/env python
# coding: utf-8

# # Static Data Analysis

# We begin by importing all the necessary libraries


# For preprocessing
import os
import sys
from glob import glob
import statistics
import numpy as np

# For training
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import time

# For exporting
import pickle


# # Analysis

# We begin our analysis by making a list of all the files that are available to us for analysis

# Path to directory
try:
    if(sys.argv[1] != None):
        if os.path.exists(sys.argv[1]):
            malware_dir = sys.argv[1]
        else:
            sys.exit("Please provide a valid malware directory.")
    else:
        sys.exit("usage: python train_static.py malware_directory benign_directory")

    if(sys.argv[2] != None):
        if os.path.exists(sys.argv[2]):
            benign_dir = sys.argv[2]
        else:
            sys.exit("Please provide a valid benign directory.")
    else:
        sys.exit("usage: python train_static.py malware_directory benign_directory")
except:
    sys.exit("usage: python train_static.py malware_directory benign_directory")


malwares = []
benigns = []

# Extract and save path of each data point
for root, dirs, files in os.walk(benign_dir):
    for file in files:
        if file == "String.txt":
            continue
        # Append file names to list
        benigns.append(os.path.join(root, file))

# Extract and save path of each data point
for root, dirs, files in os.walk(malware_dir):
    for file in files:
        # Append file names to list
        malwares.append(os.path.join(root, file))


# Our first feature is the count of the number of signs of a bad compiler.
#
# This involves leaving checksum as 0x0, using characteristic 0x10F(makes the section executable) and also using blank names for sections of the PE file.
# Good compilers generally do not generate or allow such features to exist.

def signs_of_bad_compiler(f_path):
    count = 0
    f = open(f_path, "r",
             errors="ignore", encoding="utf8")
    lines = f.read()

    count += lines.count("CheckSum:                      0x0")

    count += lines.count("Characteristics:               0x10F")

    split = lines.split("----------PE Sections----------")
    if len(split) != 1:
        split = split[1].split("----------")
        split = split[0].split("\n")
        for line in split:
            split = line.split("0x0   Name:")
            if len(split) != 1:
                name = split[1].strip()
                if name == "":
                    count += 1
    return count

# Next, we'll run an analysis on all benign files to get the top 7 most common external functions they call.
# We can use the same to determine the probablity of a file being benign by assuming it to be characteristic of benign apps.


good_props = ["MapViewOfFile", "ResumeThread", "SetWindowsHookExW",
              "CryptGenRandom", "CryptAcquireContextW", "CreateToolhelp32Snapshot",
              "CertDuplicateCertificateContext"]


def functions_of_benign(f_path):
    count = 0
    f = open(f_path, "r",
             errors="ignore", encoding="utf8")
    lines = f.read()
    for prop in good_props:
        count += lines.count(prop)
    return count

# Our next feature is the number of "Suspicious flag" warnings in the PE file


def num_of_warnings(f_path):
    count = 0
    f = open(f_path, "r",
             errors="ignore", encoding="utf8")
    lines = f.read()
    count += lines.count("Suspicious flags")
    return count

# Finally, we get to our most important feature - Entropy.
# The PE sections contain data which usually has a known entropy. Higher entropy can indicate packed data. Malicious files are commonly packed to avoid static analysis since the actual code is usually stored encrypted in one of the sections and will only be extracted at runtime.
#
# We extract the minimum, maximum and the mean of all entropies from each file.


def calc_entropy(f_path):
    entropy = []
    f = open(f_path, "r",
             errors="ignore", encoding="utf8")
    lines = f.read()
    entropy_split = lines.split("Entropy: ")
    for each in entropy_split[1:]:
        entropy.append(float(each.split(" ")[0]))
    if not bool(entropy):
        return [0, 0, 0]
    return [min(entropy), max(entropy), statistics.mean(entropy)]


# # Training

# First, we define a function to extract features by calling all the functions that we defined earlier.

def extract_features(f_path):

    features = [0, 0, 0, 0, 0, 0]

    features[0] = signs_of_bad_compiler(f_path)

    features[1] = functions_of_benign(f_path)

    features[2] = num_of_warnings(f_path)

    features[3], features[4], features[5] = calc_entropy(f_path)

    return features


# Next, we write the code to send files from our dataset for feature extraction


# Number of samples to take of each type. Set as a negative number to use entire dataset
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

x_train, x_test, y_train, y_test = train_test_split(
    x, y, test_size=0.25, random_state=42)


# Now, onto the actual trainning.
#
# We use Random Forest Classifier as the data is highly threshold based. Forest classifiers give good results on such data.


clsf = RandomForestClassifier(n_estimators=50)
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


# # Export Model

export_name = "static_model"
pickle.dump(clsf, open(export_name, 'wb'))
print("Model saved as " + export_name)
