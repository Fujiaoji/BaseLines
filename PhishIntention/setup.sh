#!/bin/bash

FILEDIR=$(pwd)

# Source the Conda configuration
CONDA_BASE=$(conda info --base)
source "$CONDA_BASE/etc/profile.d/conda.sh"

# # Create a new conda environment with Python 3.8
ENV_NAME="myenv"

# Check if the environment already exists
conda info --envs | grep -w "$ENV_NAME" > /dev/null

if [ $? -eq 0 ]; then
   # If the environment exists, activate it
   echo "Activating Conda environment $ENV_NAME"
   conda activate "$ENV_NAME"
else
   # If the environment doesn't exist, create it with Python 3.8 and activate it
   echo "Creating and activating new Conda environment $ENV_NAME with Python 3.8"
   conda create -n "$ENV_NAME" python=3.8
   conda activate "$ENV_NAME"
fi
# Set Conda environment as an environment variable
export MYENV=$(conda info --base)/envs/"$ENV_NAME"


# Get the CUDA and cuDNN versions, install pytorch, torchvision
conda activate "$ENV_NAME"
conda install typing_extensions

conda run -n "$ENV_NAME" pip install torch==1.9.0 torchvision -f \
  "https://download.pytorch.org/whl/cu111/torch_stable.html"

conda run -n "$ENV_NAME" python -m pip install detectron2 -f \
  https://dl.fbaipublicfiles.com/detectron2/wheels/cu111/torch1.9/index.html

# Install PhishIntention
conda run -n "$ENV_NAME" pip install -v .
package_location=$(conda run -n "$ENV_NAME" pip show phishintention | grep Location | awk '{print $2}')

if [ -z "PhishIntention" ]; then
  echo "Package PhishIntention not found in the Conda environment myenv."
  exit 1
else
  echo "Going to the directory of package PhishIntention in Conda environment myenv."
  cd "$package_location/phishintention" || exit
  pwd
  # download models and unzip
  file_id="1zw2MViLSZRemrEsn2G-UzHRTPTfZpaEd"
  output_file="src.zip"
  # Download the file using wget
  wget --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id='$file_id -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=$file_id" -O "$output_file" & wait
  rm -rf /tmp/cookies.txt
  # Remove the directory if it already exists
  unzip -o src.zip && echo "Unzip completed successfully"
  rm src.zip

  # download domain_map.pkl
  cd src/phishpedia_siamese
  file_id="1nTIC6311dvdY4cGsrI4c3WMndSauuHSm"
  output_file="domain_map.pkl"
  wget --load-cookies /tmp/cookies.txt "https://docs.google.com/uc?export=download&confirm=$(wget --quiet --save-cookies /tmp/cookies.txt --keep-session-cookies --no-check-certificate 'https://docs.google.com/uc?export=download&id='$file_id -O- | sed -rn 's/.*confirm=([0-9A-Za-z_]+).*/\1\n/p')&id=$file_id" -O "$output_file" & wait
  rm -rf /tmp/cookies.txt
fi

# Replace the placeholder in the YAML template
sed "s|CONDA_ENV_PATH_PLACEHOLDER|$package_location/phishintention|g" "$FILEDIR/phishintention/configs_template.yaml" > "$package_location/phishintention/configs.yaml"
cd "$FILEDIR"
conda run -n "$ENV_NAME" pip install -r requirements.txt
