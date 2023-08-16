from .phishpedia_config import *
import os
import argparse
import time
import json
from .src.util.chrome import *
# import os
import pandas as pd
os.environ["KMP_DUPLICATE_LIB_OK"]="TRUE"
import csv
from PIL import Image

#####################################################################################################################
# ** Step 1: Enter Layout detector, get predicted elements
# ** Step 2: Enter Siamese, siamese match a phishing target, get phishing target

# **         If Siamese report no target, Return Benign, None
# **         Else Siamese report a target, Return Phish, phishing target
#####################################################################################################################


def test(url, screenshot_path, ELE_MODEL, SIAMESE_THRE, SIAMESE_MODEL, LOGO_FEATS, LOGO_FILES, DOMAIN_MAP_PATH):
    '''
    Phishdiscovery for phishpedia main script
    :param url: URL
    :param screenshot_path: path to screenshot
    :param ELE_MODEL: logo detector
    :param SIAMESE_THRE: threshold for Siamese
    :param SIAMESE_MODEL: siamese model
    :param LOGO_FEATS: cached reference logo features
    :param LOGO_FILES: cached reference logo paths
    :param DOMAIN_MAP_PATH: domain map.pkl
    :return phish_category: 0 for benign 1 for phish
    :return pred_target: None or phishing target
    :return plotvis: predicted image
    :return siamese_conf: siamese matching confidence
    '''
    # 0 for benign, 1 for phish, default is benign
    phish_category = 0
    pred_target = None
    siamese_conf = None
    # print("Entering phishpedia ...")

    ####################### Step1: layout detector ##############################################
    # detectron2_pedia.inference
    pred_boxes, _, _, _ = pred_rcnn(im=screenshot_path, predictor=ELE_MODEL)
    if pred_boxes is not None:
        pred_boxes = pred_boxes.detach().cpu().numpy()

    plotvis = vis(screenshot_path, pred_boxes)
    
    # print("plot")
    # If no element is reported
    if pred_boxes is None or len(pred_boxes) == 0:
        print('No element is detected, report as benign')
        return phish_category, pred_target, plotvis, siamese_conf, pred_boxes


    # print('Entering siamese ...')
    ######################## Step2: Siamese (logo matcher) ########################################
    pred_target, matched_coord, siamese_conf = phishpedia_classifier_logo(logo_boxes=pred_boxes,
                                                                     domain_map_path=DOMAIN_MAP_PATH,
                                                                     model=SIAMESE_MODEL,
                                                                     logo_feat_list=LOGO_FEATS,
                                                                     file_name_list=LOGO_FILES,
                                                                     url=url,
                                                                     shot_path=screenshot_path,
                                                                     ts=SIAMESE_THRE)

    if pred_target is None:
        print('Did not match to any brand, report as benign')
        return phish_category, pred_target, plotvis, siamese_conf, pred_boxes

    else:
        phish_category = 1
        # Visualize, add annotations
        cv2.putText(plotvis, "Target: {} with confidence {:.4f}".format(pred_target, siamese_conf),
                    (int(matched_coord[0] + 20), int(matched_coord[1] + 20)),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 0), 2)

    return phish_category, pred_target, plotvis, siamese_conf, pred_boxes




def runit(args):
 
    start_time = time.time()
    # read testing csv
    test_df = pd.read_csv(args.input_csv)
    # the tesult csv 
    normal_csv = open(args.output_csv, "w")
    normal_csvwriter = csv.writer(normal_csv)
    normal_csvwriter.writerow(["ini_brand", "pred_brand", "pred_phish", "siamese_conf", "pic_name", "pred_path", "url"])
    # testing url, need to change column name based on the csv file column name
    for idx, row in test_df.iterrows():
        url = row["url"]
        ini_brand = row["nbrand"]
        screenshot_path = args.pic_folder + row["pic_name"].split("_")[0] + "/" + row["pic_name"]
        pred_path = args.pred_pic_folder + row["pic_name"].split(".png")[0] + "_pred" + ".png"    
                    
        phish_cate, phish_target, plotvis, siamese_conf, _ = test(url=url, screenshot_path=screenshot_path,
                                                                            ELE_MODEL=args.ELE_MODEL,
                                                                            SIAMESE_THRE=args.SIAMESE_THRE,
                                                                            SIAMESE_MODEL=args.SIAMESE_MODEL,
                                                                            LOGO_FEATS=args.LOGO_FEATS,
                                                                            LOGO_FILES=args.LOGO_FILES,
                                                                            DOMAIN_MAP_PATH=args.DOMAIN_MAP_PATH)
        try:
            normal_csvwriter.writerow([ini_brand, str(phish_target), str(phish_cate), str(siamese_conf), row["pic_name"], pred_path, url])
            if plotvis is not None:
                cv2.imwrite(pred_path, plotvis)
        except UnicodeEncodeError:
            print("------")
            pass
                     
                        
    print(str(round(time.time() - start_time, 4)))

    
