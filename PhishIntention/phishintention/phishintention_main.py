import os
import argparse
import time
import csv
import cv2

from phishintention.phishintention_config import *
from phishintention.src.AWL_detector import vis

os.environ["KMP_DUPLICATE_LIB_OK"]="TRUE"

#####################################################################################################################
# ** Step 1: Enter Layout detector, get predicted elements
# ** Step 2: Enter Siamese, siamese match a phishing target, get phishing target

# **         If Siamese report no target, Return Benign, None
# **         Else Siamese report a target, Enter CRP classifier(and HTML heuristic)

# ** Step 3: If CRP classifier(and heuristic) report it is non-CRP, go to step 4: Dynamic analysis, go back to step1
# **         Else CRP classifier(and heuristic) reports its a CRP page

# ** Step 5: If reach a CRP + Siamese report target: Return Phish, Phishing target
# ** Else: Return Benign
#####################################################################################################################


def test(url, screenshot_path, html_path, AWL_MODEL, CRP_CLASSIFIER, CRP_LOCATOR_MODEL, SIAMESE_MODEL, OCR_MODEL, SIAMESE_THRE, LOGO_FEATS, LOGO_FILES, DOMAIN_MAP_PATH):
    '''
    Phish-discovery main script
    :param url: URL
    :param screenshot_path: path to screenshot
    :return phish_category: 0 for benign, 1 for phish
    :return phish_target: None/brand name
    :return plotvis: predicted image
    :return siamese_conf: matching confidence reported by siamese
    :return dynamic: go through dynamic analysis or not
    :return time breakdown
    '''
    
    waive_crp_classifier = False
    

    while True:
        # 0 for benign, 1 for phish, default is benign
        phish_category = 0
        pred_target = None
        siamese_conf = None
        print("Entering phishintention")

        ####################### Step1: layout detector ##############################################
        print("step 1: layout detector")
        pred_classes, pred_boxes, pred_scores = element_recognition(img=screenshot_path, model=AWL_MODEL)
        print("pred_classes, pred_boxes, pred_scores", len(pred_classes), len(pred_boxes), pred_scores)
        plotvis = vis(screenshot_path, pred_boxes, pred_classes)
        

        # If no element is reported
        if pred_boxes is None or len(pred_boxes) == 0:
            print('No element is detected, report as benign')
            return phish_category, pred_target, plotvis, siamese_conf, pred_boxes, pred_classes

        # domain already in targetlist
        print("step 1: layout detector->check url domain if in the target list")
        
        with open(DOMAIN_MAP_PATH, 'rb') as handle:
            domain_map = pickle.load(handle)
        existing_brands = domain_map.keys()
        existing_domains = [y for x in list(domain_map.values()) for y in x]
        existing_brands = [item.lower() for item in existing_brands]
        # if query_domain in existing_brands or query_domain in existing_domains:
        #     print("urldomain {} in maintained list".format(query_domain))
        #     return phish_category, pred_target, plotvis, siamese_conf, pred_boxes, pred_classes
        query_domain = tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix
        query_brand = tldextract.extract(url).domain
        if query_brand in existing_brands or query_domain in existing_domains:
            print("url brand: {}, url domain {} in maintained list".format(query_brand, query_domain))
            return phish_category, pred_target, plotvis, siamese_conf, pred_boxes, pred_classes

        ######################## Step2: Siamese (logo matcher) ########################################
        print("url brand: {}, url domain {} not in maintained list".format(query_brand, query_domain))
        print("step 2: Siamese (logo matcher)")
        pred_target, matched_coord, siamese_conf = phishpedia_classifier_OCR(pred_classes=pred_classes, pred_boxes=pred_boxes, 
                                        domain_map_path=DOMAIN_MAP_PATH, model=SIAMESE_MODEL,
                                        ocr_model = OCR_MODEL,
                                        logo_feat_list=LOGO_FEATS, file_name_list=LOGO_FILES,
                                        url=url, shot_path=screenshot_path,
                                        ts=SIAMESE_THRE)

        if pred_target is None:
            print('Did not match to any brand, report as benign')
            return phish_category, pred_target, plotvis, siamese_conf, pred_boxes, pred_classes


        ######################## Step3: CRP checker (if a target is reported) #################################
        print('step 3: CRP checker. A target is reported by siamese, enter CRP classifier')
        if waive_crp_classifier: # only run dynamic analysis ONCE
            break
            
        if pred_target is not None:
            # CRP HTML heuristic
            # html_path = screenshot_path.replace("shot.png", "html.txt")
            print('step 3 CRP -> check html')
            cre_pred = html_heuristic(html_path)
            
            if cre_pred == 1: # if HTML heuristic report as nonCRP
                # CRP classifier
                print("html NonCRP")
                print('step 3-> check classifier')
                cre_pred, cred_conf, _  = credential_classifier_mixed_al(img=screenshot_path, coords=pred_boxes,
                                                                            types=pred_classes, model=CRP_CLASSIFIER)
            else:
                print("html hasCRP")
#
#           ######################## Step4: Dynamic analysis #################################
            
            print('step 4: dynamic, not use')
            if cre_pred == 1: # Non-credential page
                phish_category = 0  # Report as benign
                print('step 4: Screenshot no CRP page')
                return phish_category, pred_target, plotvis, siamese_conf, pred_boxes, pred_classes
            else: # already a CRP page
                phish_category = 1
                print('step 4: already a CRP page, continue')
                break
#
    ######################## Step5: Return #################################    
    if pred_target is not None: # 只是CRP会经过这个
        print('Phishing is found!')
        phish_category = 1
        # Visualize, add annotations
        cv2.putText(plotvis, "Target: {} with confidence {:.4f}".format(pred_target, siamese_conf),
                    (int(matched_coord[0] + 20), int(matched_coord[1] + 20)),
                    cv2.FONT_HERSHEY_SIMPLEX, 0.8, (0, 0, 0), 2)
        
    return phish_category, pred_target, plotvis, siamese_conf, pred_boxes, pred_classes

def runit(AWL_MODEL, CRP_CLASSIFIER, CRP_LOCATOR_MODEL, SIAMESE_MODEL, OCR_MODEL, SIAMESE_THRE, LOGO_FEATS, LOGO_FILES, DOMAIN_MAP_PATH):
    start_time = time.time()
    # 读取url.txt
    brand_list = []
    url_list = []
    with open("../dataset/phishintention/test_with_benign_url/00_benign/url.txt", "r") as url_f:
        for line in url_f.readlines():
            line = line.strip().split(",")
            brand_list.append(line[0])
            url_list.append(line[1])

    domain_list = [tldextract.extract(x).domain + '.' + tldextract.extract(x).suffix for x in url_list]
    
    # 循环每个brand的每一个类别
    tar_folder = ["00_benign", "01_benign_delete_logo", "02_benign_only_logo", "03_benign_add_english_text", "04_benign_combine_logo"]
    # pred_folder_path = "../dataset/phishintention/squatting_results84/squatting_pred_src/"
    pred_folder_path = "../dataset/phishintention/questions/q10/"

    for index, brand in enumerate(brand_list):
        print("--------------" + brand + "--------------")
        normal_csv = open("../dataset/phishintention/questions/q10/" + domain_list[index] + ".csv", "w")
        # normal_csv = open("../dataset/phishintention/squatting_results84/squatting_csv/" + domain_list[index] + ".csv", "w")
        normal_csvwriter = csv.writer(normal_csv)
        normal_csvwriter.writerow(["ini_brand", "pred_brand", "url_tag", "pred_phish", "benign_domain", "tld_domain", "squat_or_apwg_domain", "squat_type", "folder_type", "siamese_conf", "pic_name", "des_pic_name", "url"])
        # 对原始图片，直接每一个brand测试很多url就行
        for idx, folder_name in enumerate(tar_folder):
            ini_brand = brand
            html = "../dataset/phishintention/test_with_benign_url/00_benign/" + str(index) + ".html"
            # benign url
            benign_url = url_list[index]
            # squatting url
            squatting_url_list = []
            squatting_type_list = []
            with open("../dataset/phishintention/squatting_url/"+domain_list[index]+".txt", "r") as sq_f:
                for sline in sq_f.readlines():
                    sline = sline.strip().split(",")
                    squatting_url_list.append(sline[0])
                    squatting_type_list.append(sline[1].strip())
            
            # random apwg url not in squatting
            random100 = pd.read_csv("../dataset/phishintention/test_with_phish_url/55_test_apwg_url_domain_sample_100_" + str(index) + ".csv")
            # other target brand url
            other_url_list = pd.read_csv("../dataset/phishintention/test_with_phish_url/66_test_apwg_url_other_brand_sample_100_" + str(index) + ".csv")

            # if idx <= 2:
            #     scr_path = "../dataset/phishintention/test_with_benign_url/" + folder_name + "/" + str(index) + ".png"
            #     # benign url
            #     print("*** 0-benign url")
            #     pred_path = pred_folder_path + str(index) + "_" + str(idx) + "_0_pred" + ".png"
                

            #     phish_cate, phish_target, plotvis, siamese_conf, _, _ = test(url=benign_url, screenshot_path=scr_path, html_path=html,
            #                                                                                 AWL_MODEL=AWL_MODEL, CRP_CLASSIFIER=CRP_CLASSIFIER, CRP_LOCATOR_MODEL=CRP_LOCATOR_MODEL,
            #                                                                                 SIAMESE_MODEL=SIAMESE_MODEL, OCR_MODEL=OCR_MODEL,
            #                                                                                 SIAMESE_THRE=SIAMESE_THRE, LOGO_FEATS=LOGO_FEATS, LOGO_FILES=LOGO_FILES,
            #                                                                                 DOMAIN_MAP_PATH=DOMAIN_MAP_PATH)
                
            #     try:
            #         normal_csvwriter.writerow([ini_brand, str(phish_target), "benign", str(phish_cate), domain_list[index], domain_list[index], domain_list[index], "benign", folder_name, str(siamese_conf), str(index) + ".png", pred_path, benign_url])
            #         if plotvis is not None:
            #             cv2.imwrite(pred_path, plotvis)
            #     except UnicodeEncodeError:
            #         print("------")
            #         pass
            #     # squatting url
            #     print("*** 1-squatting url")
            #     for iidx, item in enumerate(squatting_url_list):
            #         print("------", iidx, item, "------")
            #         squat_url = "https://" +item
            #         tld_domain = tldextract.extract(squat_url).domain + '.' + tldextract.extract(squat_url).suffix
            #         pred_path = pred_folder_path + str(index) + "_" + str(idx) + "_" + str(iidx) + "_1_pred" + ".png"
            #         phish_cate1, phish_target1, plotvis1, siamese_conf1, pred_boxes1, pred_classes1 = test(url=squat_url, screenshot_path=scr_path,html_path=html,
            #                                                                                 AWL_MODEL=AWL_MODEL, CRP_CLASSIFIER=CRP_CLASSIFIER, CRP_LOCATOR_MODEL=CRP_LOCATOR_MODEL,
            #                                                                                 SIAMESE_MODEL=SIAMESE_MODEL, OCR_MODEL=OCR_MODEL,
            #                                                                                 SIAMESE_THRE=SIAMESE_THRE, LOGO_FEATS=LOGO_FEATS, LOGO_FILES=LOGO_FILES,
            #                                                                                 DOMAIN_MAP_PATH=DOMAIN_MAP_PATH)
            #         try:
            #             normal_csvwriter.writerow([ini_brand, str(phish_target1), "squatting", str(phish_cate1), domain_list[index], tld_domain, item, squatting_type_list[iidx], folder_name, str(siamese_conf1), str(index) + ".png", pred_path, squat_url])

            #             # if plotvis1 is not None:
            #             #     cv2.imwrite(pred_path, plotvis1)
            #         except UnicodeEncodeError:
            #             print("------")
            #             continue

            #     # random url not in squatting domain
            #     print("**** 2-random url")
            #     for ridx, row in random100.iterrows():
            #         print("------", ridx, row["url_x"], "------")
            #         rd_url = row["url_x"]
            #         squat_or_apwg_domain = row["domain"]
            #         tld_domain = tldextract.extract(rd_url).domain + '.' + tldextract.extract(rd_url).suffix
            #         pred_path = pred_folder_path + str(index) + "_" + str(idx) + "_" + str(ridx) + "_2_pred" + ".png"
            #         phish_cate2, phish_target2, plotvis2, siamese_conf2, pred_boxes2, pred_classes2 = test(url=rd_url, screenshot_path=scr_path,html_path=html,
            #                                                                                 AWL_MODEL=AWL_MODEL, CRP_CLASSIFIER=CRP_CLASSIFIER, CRP_LOCATOR_MODEL=CRP_LOCATOR_MODEL,
            #                                                                                 SIAMESE_MODEL=SIAMESE_MODEL, OCR_MODEL=OCR_MODEL,
            #                                                                                 SIAMESE_THRE=SIAMESE_THRE, LOGO_FEATS=LOGO_FEATS, LOGO_FILES=LOGO_FILES,
            #                                                                                 DOMAIN_MAP_PATH=DOMAIN_MAP_PATH)
            #         try:
            #             normal_csvwriter.writerow([ini_brand, str(phish_target2), "random", str(phish_cate2), domain_list[index], tld_domain, squat_or_apwg_domain, "random", folder_name, str(siamese_conf2), str(index) + ".png", pred_path, rd_url])

            #             if plotvis2 is not None:
            #                 cv2.imwrite(pred_path, plotvis2)
            #         except UnicodeEncodeError:
            #             print("------")
            #             continue
            #     # other squatting url
            #     print("**** 3-other url")
            #     for oidx, oitem in other_url_list.iterrows():
                    
            #         othersquat_url = "https://" + oitem["other_domain"]
            #         tld_domain = tldextract.extract(othersquat_url).domain + '.' + tldextract.extract(othersquat_url).suffix
            #         print("------", oidx, tld_domain, "------")

            #         pred_path = pred_folder_path + str(index) + "_" + str(idx) + "_" + str(oidx) + "_3_pred" + ".png"
            #         phish_cate3, phish_target3, plotvis3, siamese_conf3, pred_boxes3, pred_classes3 = test(url=othersquat_url, screenshot_path=scr_path,html_path=html,
            #                                                                             AWL_MODEL=AWL_MODEL, CRP_CLASSIFIER=CRP_CLASSIFIER, CRP_LOCATOR_MODEL=CRP_LOCATOR_MODEL,
            #                                                                             SIAMESE_MODEL=SIAMESE_MODEL, OCR_MODEL=OCR_MODEL,
            #                                                                             SIAMESE_THRE=SIAMESE_THRE, LOGO_FEATS=LOGO_FEATS, LOGO_FILES=LOGO_FILES,
            #                                                                             DOMAIN_MAP_PATH=DOMAIN_MAP_PATH)
            #         try:
            #             normal_csvwriter.writerow([ini_brand, str(phish_target3), "other", str(phish_cate3), domain_list[index], tld_domain, oitem["other_domain"], oitem["other_domain_type"], folder_name, str(siamese_conf3), str(index) + ".png", pred_path, othersquat_url])

            #             # if plotvis3 is not None:
            #             #     cv2.imwrite(pred_path, plotvis3)
            #         except UnicodeEncodeError:
            #             print("------")
            #             continue
            
            # else:
            if idx == 4:
                pic_list = os.listdir("../dataset/phishintention/test_with_benign_url/" + folder_name + "/")
                pic_list = [item for item in pic_list if item.startswith(str(index) +"-")]
                for screenshot_name in pic_list:
                    print("---", screenshot_name, "---")
                    scr_path = "../dataset/phishintention/test_with_benign_url/" + folder_name + "/" + screenshot_name
                    # # benign url
                    # pred_path = pred_folder_path + str(index) + "_" + str(idx) + "_" + screenshot_name.replace(".png", "_0_pred.png") 
                    # phish_cate, phish_target, plotvis, siamese_conf, pred_boxes, pred_classes = test(url=benign_url, screenshot_path=scr_path,html_path=html,
                    #                                                                     AWL_MODEL=AWL_MODEL, CRP_CLASSIFIER=CRP_CLASSIFIER, CRP_LOCATOR_MODEL=CRP_LOCATOR_MODEL,
                    #                                                                         SIAMESE_MODEL=SIAMESE_MODEL, OCR_MODEL=OCR_MODEL,
                    #                                                                         SIAMESE_THRE=SIAMESE_THRE, LOGO_FEATS=LOGO_FEATS, LOGO_FILES=LOGO_FILES,
                    #                                                                         DOMAIN_MAP_PATH=DOMAIN_MAP_PATH)
                
                    # try:
                    #     normal_csvwriter.writerow([ini_brand, str(phish_target), "benign", str(phish_cate), domain_list[index], domain_list[index], domain_list[index], "benign", folder_name, str(siamese_conf), screenshot_name, pred_path, benign_url])
                    #     if plotvis is not None:
                    #         cv2.imwrite(pred_path, plotvis)
                    # except UnicodeEncodeError:
                    #     print("------")
                    #     pass
                    
                    # squatting url
                    for iidx, item in enumerate(squatting_url_list):
                        print("---", iidx, item, "---")
                        squat_url = "https://" +item
                        tld_domain = tldextract.extract(squat_url).domain + '.' + tldextract.extract(squat_url).suffix
                        pred_path = pred_folder_path + str(index) + "_" + str(idx) + "_" + str(iidx) + "_" + screenshot_name.replace(".png", "_1_pred.png") 
                        phish_cate1, phish_target1, plotvis1, siamese_conf1, _, _ = test(url=squat_url, screenshot_path=scr_path,html_path=html,
                                                                                            AWL_MODEL=AWL_MODEL, CRP_CLASSIFIER=CRP_CLASSIFIER, CRP_LOCATOR_MODEL=CRP_LOCATOR_MODEL,
                                                                                            SIAMESE_MODEL=SIAMESE_MODEL, OCR_MODEL=OCR_MODEL,
                                                                                            SIAMESE_THRE=SIAMESE_THRE, LOGO_FEATS=LOGO_FEATS, LOGO_FILES=LOGO_FILES,
                                                                                            DOMAIN_MAP_PATH=DOMAIN_MAP_PATH)
                        try:
                            normal_csvwriter.writerow([ini_brand, str(phish_target1), "squatting", str(phish_cate1), domain_list[index], tld_domain, item, squatting_type_list[iidx], folder_name, str(siamese_conf1), screenshot_name, pred_path, squat_url])
                            if plotvis1 is not None:
                                cv2.imwrite(pred_path, plotvis1)
                        except UnicodeEncodeError:
                            print("------")
                            continue

                    # # random url
                    # for ridx, row in random100.iterrows():
                    #     rd_url = row["url_x"]
                    #     rd_apwg_domain = row["domain"]
                    #     tld_domain = tldextract.extract(rd_url).domain + '.' + tldextract.extract(rd_url).suffix
                    #     pred_path = pred_folder_path + str(index) + "_" + str(idx) + "_" + str(ridx) + "_" + screenshot_name.replace(".png", "_2_pred.png")
                    #     phish_cate2, phish_target2, plotvis2, siamese_conf2, _, _ = test(url=rd_url, screenshot_path=scr_path,html_path=html,
                    #                                                                         AWL_MODEL=AWL_MODEL, CRP_CLASSIFIER=CRP_CLASSIFIER, CRP_LOCATOR_MODEL=CRP_LOCATOR_MODEL,
                    #                                                                         SIAMESE_MODEL=SIAMESE_MODEL, OCR_MODEL=OCR_MODEL,
                    #                                                                         SIAMESE_THRE=SIAMESE_THRE, LOGO_FEATS=LOGO_FEATS, LOGO_FILES=LOGO_FILES,
                    #                                                                         DOMAIN_MAP_PATH=DOMAIN_MAP_PATH)
                    #     try:
                    #         normal_csvwriter.writerow([ini_brand, str(phish_target2), "random", str(phish_cate2), domain_list[index], tld_domain, rd_apwg_domain, "random", folder_name, str(siamese_conf2), screenshot_name, pred_path, rd_url])

                    #         if plotvis2 is not None:
                    #             cv2.imwrite(pred_path, plotvis2)
                    #     except UnicodeEncodeError:
                    #         print("------")
                    #         continue
                    # # other squatting url
                    # for oidx, oitem in other_url_list.iterrows():
                    #     othersquat_url = "https://" + oitem["other_domain"]
                    #     tld_domain = tldextract.extract(othersquat_url).domain + '.' + tldextract.extract(othersquat_url).suffix
                    #     pred_path = pred_folder_path + str(index) + "_" + str(idx) + "_" + str(oidx) + "_" + screenshot_name.replace(".png", "_3_pred.png")
                    #     phish_cate3, phish_target3, plotvis3, siamese_conf3, _, _ = test(url=othersquat_url, screenshot_path=scr_path,html_path=html,
                    #                                                                         AWL_MODEL=AWL_MODEL, CRP_CLASSIFIER=CRP_CLASSIFIER, CRP_LOCATOR_MODEL=CRP_LOCATOR_MODEL,
                    #                                                                         SIAMESE_MODEL=SIAMESE_MODEL, OCR_MODEL=OCR_MODEL,
                    #                                                                         SIAMESE_THRE=SIAMESE_THRE, LOGO_FEATS=LOGO_FEATS, LOGO_FILES=LOGO_FILES,
                    #                                                                         DOMAIN_MAP_PATH=DOMAIN_MAP_PATH)
                    #     try:
                    #         normal_csvwriter.writerow([ini_brand, str(phish_target3), "other", str(phish_cate3), domain_list[index], tld_domain, oitem["other_domain"], oitem["other_domain_type"], folder_name, str(siamese_conf3), screenshot_name, pred_path, othersquat_url])

                    #         if plotvis3 is not None:
                    #             cv2.imwrite(pred_path, plotvis3)
                    #     except UnicodeEncodeError:
                    #         print("------")
                    #         continue

    end_time = time.time() - start_time
    print(end_time)










if __name__ == "__main__":

    # os.environ["CUDA_VISIBLE_DEVICES"]="1"
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', "--folder", help='Input folder path to parse',  default='./datasets/test_sites')
    parser.add_argument('-r', "--results", help='Input results file name', default='./test_intention.txt')
    parser.add_argument('-c', "--config", help='Config file path', default=None)
    parser.add_argument('-d', '--device', help='device', choices=['cuda', 'cpu'], required=True)
    args = parser.parse_args()

    AWL_MODEL, CRP_CLASSIFIER, CRP_LOCATOR_MODEL, SIAMESE_MODEL, OCR_MODEL, SIAMESE_THRE, LOGO_FEATS, LOGO_FILES, DOMAIN_MAP_PATH = load_config(args.config,
                                                                                                                                                device=args.device)
    runit(args.folder, args.results, AWL_MODEL, CRP_CLASSIFIER, CRP_LOCATOR_MODEL, SIAMESE_MODEL, OCR_MODEL, SIAMESE_THRE, LOGO_FEATS, LOGO_FILES, DOMAIN_MAP_PATH)







