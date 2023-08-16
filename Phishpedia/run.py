import os
import argparse

from datetime import datetime
from phishpedia.phishpedia_main import *


os.environ['KMP_DUPLICATE_LIB_OK']='True'


if __name__ == '__main__':
    ELE_MODEL, SIAMESE_THRE, SIAMESE_MODEL, LOGO_FEATS, LOGO_FILES, DOMAIN_MAP_PATH = load_config(None)

    date = datetime.today().strftime('%Y-%m-%d')
    print('Today is:', date)
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', "--input_csv",
                        default='dataset/test.csv',
                        help='Input dataset csv file')
    parser.add_argument('-pic_folder', "--pic_folder",
                        default='/dataset/fujiao/00_APWG/00_screenshots/',
                        help='Testing picture folder path')
    parser.add_argument('-r', "--output_csv", default="result/phishpedia_{}.csv".format(date),
                        help='Output results csv')
    parser.add_argument('-pic_out_folder', "--pred_pic_folder",
                        default='result/pred_pic_result/',
                        help='Testing picture folder path')
    parser.add_argument('--repeat', action='store_true')
    parser.add_argument('--no_repeat', action='store_true')

    args = parser.parse_args()
    print(args)
    args.ELE_MODEL = ELE_MODEL
    args.SIAMESE_THRE = SIAMESE_THRE
    args.SIAMESE_MODEL = SIAMESE_MODEL
    args.LOGO_FEATS = LOGO_FEATS
    args.LOGO_FILES = LOGO_FILES
    args.DOMAIN_MAP_PATH =DOMAIN_MAP_PATH
    
    runit(args)
    print('Process finish')
    # wget --no-check-certificate "https://drive.google.com/uc?export=download&id=${1ymkGrDT8LpTmohOOOnA2yjhEny1XYenj}" -O ${benign_25k}
    # wget --load-cookies /tmp/cookies.txt "https://drive.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://drive.google.com/uc?export=download&id=${12ypEMPRQ43zGRqHGut0Esq2z5en0DH4g}' -O- | sed -rn 's/.confirm=([0-9A-Za-z_]+)./\1\n/p')&id=${12ypEMPRQ43zGRqHGut0Esq2z5en0DH4g}" -O ${phish_sample_30k.zip} && rm -rf /tmp/cookies.txt

