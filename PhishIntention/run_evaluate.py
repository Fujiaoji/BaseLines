import os
import csv
import time
import argparse
import pandas as pd

from datetime import datetime
from phishintention.src.AWL_detector import *
from phishintention.src.crp_classifier import *
from phishintention.src.OCR_aided_siamese import *

os.environ["CUDA_VISIBLE_DEVICES"]="0"


def phishintention_eval(args, siamese_ts):
    '''
    Run phishintention evaluation
    :param data_dir: data folder dir
    :param mode: phish|benign
    :param siamese_ts: siamese threshold
    :param write_txt: txt path to write results
    :return:
    '''
    dir_folder = "/dataset/fujiao/00_APWG/90_phishintention_730_results/"
    normal_csv = open(args.output_csv, "w")
    normal_csvwriter = csv.writer(normal_csv)
    normal_csvwriter.writerow(["ini_brand", "pred_brand", "pred_phish", "siamese_conf", "pic_name", "pred_path", "url"])
    
    # testing url, need to change column name based on the csv file column name
    df = pd.read_csv(args.input_csv)
  
    start_time = time.time()
    for index, row in df.iterrows():
        phish_category = 0  # 0 for benign, 1 for phish
        pred_target = None  # predicted target, default is None

        url = row["url"]
        nbrand = row["nbrand"]
        img_path = args.pic_folder + row["pic_name"].split("_")[0] + "/" + row["pic_name"]
        html_path = args.html_folder_path + row["pic_name"].split(".")[0] + "_0.html"
        
        # Element recognition module
        pred_classes, pred_boxes, pred_scores = element_recognition(img=img_path, model=ele_model)

        # If no element is reported
        if len(pred_boxes) == 0:
            phish_category = 0  # Report as benign

        # If at least one element is reported
        else:
            # Credential heuristic module
            cred_conf = None
            # CRP HTML heuristic
            cre_pred = html_heuristic(html_path)
            # Credential classifier module
            if cre_pred == 1:  # if HTML heuristic report as nonCRP
                cre_pred, cred_conf, _ = credential_classifier_mixed_al(img=img_path, coords=pred_boxes,
                                                                        types=pred_classes, model=cls_model)

            # Non-credential page
            if cre_pred == 1:  # if non-CRP
                phish_category = 0  # Report as benign

            # Credential page
            else:
                # Phishpedia module

                pred_target, _, siamese_conf = phishpedia_classifier_OCR(pred_classes=pred_classes, pred_boxes=pred_boxes,
                                                          domain_map_path=domain_map_path,
                                                          model=pedia_model,
                                                          ocr_model=ocr_model,
                                                          logo_feat_list=logo_feat_list, file_name_list=file_name_list,
                                                          url=url,
                                                          shot_path=img_path,
                                                          ts=siamese_ts)


                # Phishpedia reports target
                if pred_target is not None:
                    phish_category = 1  # Report as suspicious

                # Phishpedia does not report target
                else:  # Report as benign
                    phish_category = 0
        pred_brand = brand_converter(pred_target) if pred_target is not None else None
        normal_csvwriter.writerow([row["pic_name"], nbrand, pred_brand, str(phish_category), str(siamese_conf), url])
    endtime = time.time() - start_time
    print("using time : {}".format(endtime))
if __name__ == '__main__':
    date = datetime.today().strftime('%Y-%m-%d')
    print('Today is:', date)
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', "--input_csv",
                        default='dataset/test.csv',
                        help='Input dataset csv file')
    parser.add_argument('-pic_folder', "--pic_folder",
                        default='/dataset/fujiao/00_APWG/00_screenshots/',
                        help='Testing picture folder path')
    parser.add_argument('-r', "--output_csv", default="result/phishintention_{}.csv".format(date),
                        help='Output results csv')
    parser.add_argument('-pic_out_folder', "--pred_pic_folder",
                        default='result/pred_pic_result/',
                        help='Pred picture folder path')
    parser.add_argument('-html_folder_path', "--html_folder_path",
                        default='/dataset/fujiao/01_APWG/01_apwg_cleaned_1250406_html/',
                        help='APWG html folder path')

    parser.add_argument('--repeat', action='store_true')
    parser.add_argument('--no_repeat', action='store_true')

    args = parser.parse_args()
    
    anaconda_path = "/home/fujiao/anaconda3/envs/myenv/lib/python3.8/site-packages/phishintention/"
    rcnn_weights_path = anaconda_path + 'src/AWL_detector_utils/output/website_lr0.001/model_final.pth'                   
    rcnn_cfg_path = anaconda_path + "src/AWL_detector_utils/configs/faster_rcnn_web.yaml"
    checkpoint = anaconda_path + "src/crp_classifier_utils/output/Increase_resolution_lr0.005/BiT-M-R50x1V2_0.005.pth.tar"
    weights_path = anaconda_path + "src/OCR_siamese_utils/output/targetlist_lr0.01/bit.pth.tar"
    ocr_weights_path = anaconda_path + "src/OCR_siamese_utils/demo_downgrade.pth.tar"
    targetlist_path = anaconda_path + "src/phishpedia_siamese/expand_targetlist/"
    domain_map_path = anaconda_path + "src/phishpedia_siamese/domain_map.pkl"
    
    ele_cfg, ele_model = element_config(rcnn_weights_path=rcnn_weights_path, rcnn_cfg_path=rcnn_cfg_path)

    args.ele_model = ele_model
    args.ele_cfg = ele_cfg

    cls_model = credential_config(checkpoint=checkpoint, model_type='mixed')
    pedia_model, ocr_model, logo_feat_list, file_name_list = phishpedia_config_OCR(num_classes=277,
                                                                                   weights_path=weights_path, 
                                                                                   ocr_weights_path=ocr_weights_path
                                                                                   targetlist_path=targetlist_path)
    print('Number of protected logos = {}'.format(str(len(logo_feat_list))))

    phishintention_eval(args, siamese_ts=0.87)

            
 



