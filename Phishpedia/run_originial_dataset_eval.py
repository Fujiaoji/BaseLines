import os
import time
import argparse

from pathlib import Path
from datetime import datetime
from multiprocessing import Process
from phishpedia.phishpedia_main import *

os.environ['KMP_DUPLICATE_LIB_OK']='True'

def phishpedia_eval(args, ELE_MODEL, SIAMESE_THRE, SIAMESE_MODEL, LOGO_FEATS, LOGO_FILES, DOMAIN_MAP_PATH):
    # csv contains the results
    normal_csv = open(args.output_csv, "w")
    normal_csvwriter = csv.writer(normal_csv)
    normal_csvwriter.writerow(["folder_name", "true_brand", "pred_brand", "phish", "siamese_conf", "url"])
  
    start_time = time.time()
    data_dir = args.input_folder

    index = 0
    for folder in os.listdir(data_dir):
        print("{}-{}".format(index, folder))
        index += 1
        phish_category = 0  # 0 for benign, 1 for phish
        pred_target = None  # predicted target, default is None
        url = None
        siamese_conf = 0
        img_path = os.path.join(data_dir, folder, 'shot.png')
        # html_path = os.path.join(data_dir, folder, 'html.txt')

        if not os.path.exists(img_path):  # screenshot not exist
            print("{} screenshot not exist".format(folder))
            continue
        
        if args.mode == 'phish':
            try:
                url = eval(open(os.path.join(data_dir, folder, 'info.txt'), encoding="ISO-8859-1").read())
                url = url['url'] if isinstance(url, dict) else url
            except:
                print("{} do not have url".format(folder))
        else:
            try:
                url = open(os.path.join(data_dir, folder, 'info.txt'), encoding="ISO-8859-1").read()
            except:
                url = 'https://www.' + folder
        

        ####################### Step1: layout detector ##############################################
        # detectron2_pedia.inference
        pred_boxes, _, _, _ = pred_rcnn(im=img_path, predictor=ELE_MODEL)
        pred_boxes = pred_boxes.detach().cpu().numpy()
        if len(pred_boxes) == 0:
            phish_category = 0  # Report as benign

        # If at least one element is reported
        else:
            ######################## Step2: Siamese (logo matcher) ########################################
            pred_target, _, siamese_conf = phishpedia_classifier_logo(logo_boxes=pred_boxes,
                                                                            domain_map_path=DOMAIN_MAP_PATH,
                                                                            model=SIAMESE_MODEL,
                                                                            logo_feat_list=LOGO_FEATS,
                                                                            file_name_list=LOGO_FILES,
                                                                            url=url,
                                                                            shot_path=img_path,
                                                                            ts=SIAMESE_THRE)
            # Phishpedia reports target
            if pred_target is not None:
                phish_category = 1  # Report as suspicious

            # Phishpedia does not report target
            else:  # Report as benign
                phish_category = 0


        true_brand = brand_converter(folder.split('+')[0])
        pred_brand = brand_converter(pred_target) if pred_target is not None else None
        normal_csvwriter.writerow([folder, true_brand, pred_brand, str(phish_category), str(siamese_conf), url])
    end_time = time.time() - start_time
    print("use {} time".format(end_time))



if __name__ == '__main__':
    date = datetime.today().strftime('%Y-%m-%d')
    print('Today is:', date)

    parser = argparse.ArgumentParser()
    
    parser.add_argument('-f', "--input_folder",
                        default="/dataset/fujiao/baseline_dataset/phishpedia_phishintention_dataset/benign_25k",
                        help='Input folder path to parse')
    
    parser.add_argument('-r', "--output_csv", default="result/phishpedia_{}.csv".format(date),
                        help='Output results file name')
    parser.add_argument('--repeat', action='store_true')
    parser.add_argument('--no_repeat', action='store_true')

    args = parser.parse_args()
    args.mode = "benign"

    ELE_MODEL, SIAMESE_THRE, SIAMESE_MODEL, LOGO_FEATS, LOGO_FILES, DOMAIN_MAP_PATH = load_config(None)
    
    
    
    phishpedia_eval(args, ELE_MODEL, SIAMESE_THRE, SIAMESE_MODEL, LOGO_FEATS, LOGO_FILES, DOMAIN_MAP_PATH)
    print('Process finish')
    

