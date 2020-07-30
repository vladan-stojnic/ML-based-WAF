# ML-based-WAF

This respository contains the code for machine learning based web application firewall written in Python 3.8. This WAF can detect sql injection, xss, path-traversal and commqand injection attacks. It can also detect long parameters as possible parameter tampering attacks. Repository also contains the code for simple REST service that can be used as target.

Code for processing the datasets is located in Dataset directory. To run cleaning notebooks you need to download used datasets and place them in Dataset directory.
*  ECML/PKDD 2007 dataset [Link](http://www.lirmm.fr/pkdd2007-challenge/)
*  HTTP parameters dataset [Link](https://github.com/Morzeux/HttpParamsDataset)
*  XSS dataset [Link](https://www.kaggle.com/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning)

Code for classifiers training is located in Classifier directory. ThreatPrediction notebook contains the code for training SVM classifier using TF-IDF features for sql injection, xss, path-traversal and commqand injection attacks. ParameterTamperingClassifer notebook contains the code for training decission tree based classifier for parameter tampering.

WAF directory contains the code for running the WAF. To run the WAF use:
```
sudo python sniffing.py [--port 5000]
```
This code needs to be run using admin priviledges as it sniffs the network.

To see the report from the WAF you can use simple dashborad that is located in WAF directory.
```
python dashboard.py
```

## Caution

This WAF shouldn't be used in production as it was created only as a fun side project and wasn't properly tested.