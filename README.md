# NetGPT

![](/images/NetGPT.png "NetGPT")

## Requirements
```
Python >= 3.6
CUDA: 11.4
torch >= 1.1
six >= 1.12.0
scapy == 2.4.4
numpy == 1.19.2
shutil, random, json, pickle, binascii, flowcontainer, argparse, packaging, tshark
```

## Reproducing the results in the paper

You can fine-tune the model using [pre-trained NetGPT model](https://drive.google.com/file/d/1GNbWtVgrG9XcuApgkSl1hDRTsDXqm12R/view?usp=drive_link) and processed dataset we provide (we will give the corresponding files below). In addition, we will give the details of data preprocessing and model pretraining later.

Note: this code is built upon [UER-py](https://github.com/dbiir/UER-py). We sincerely appreciate the authors’ contributions.

### Finetuning NetGPT for Traffic Understanding Tasks

You can reproduce the results of the understanding tasks using the [provided processed dataset for understanding task](https://drive.google.com/drive/folders/1FBPrdFLm7qnCyPtUdTLGmPx_r3xLZqor?usp=sharing).

```
python3 finetune/run_understanding.py  --pretrained_model_path pretrained_model.bin \
                                                  --output_model_path models/finetuned_model.bin \
                                                  --vocab_path models/encryptd_vocab.txt \
                                                  --config_path models/gpt2/config.json \
                                                  --train_path finetune_dataset/train_dataset.tsv \
                                                  --dev_path finetune_dataset/valid_dataset.tsv \
                                                  --test_path finetune_dataset/test_dataset.tsv \
                                                  --epochs_num 10 \
                                                  --batch_size 32 \
                                                  --labels_num 2 \
                                                  --pooling mean
```

### Finetuning NetGPT for Traffic Generation Tasks

You can reproduce the results of the generation tasks using the [provided processed dataset for generation task](https://drive.google.com/drive/folders/1zia8lT6HTEyp3mvKDygaFK6KfrNCf3ou?usp=sharing), note that don't need to set "labels_num".

```
python3 finetune/run_generation.py    --pretrained_model_path pretrained_model.bin \
                                      --output_model_path models/finetuned_model.bin \
                                      --vocab_path models/encryptd_vocab.txt \
                                      --config_path models/gpt2/config.json \
                                      --train_path datasets/train_dataset.tsv \
                                      --dev_path datasets/valid_dataset.tsv \
                                      --test_path datasets/test_dataset.tsv \
                                      --learning_rate 1e-5 \
                                      --epochs_num 10 \
                                      --batch_size 16 \
                                      --pooling mean \
                                      --seq_length 256 \
                                      --tgt_seq_length 4
```

## Data Preprocessing

### Data Preprocessing for Model Pre-training

#### Converting traffic into a corpus

In order to pre-train the model, we first need to convert the traffic data into a corpus. Note you'll need to change the file paths and some configures at the top of the "main.py" file. Specifically, you need to

1. set the variable pcap_path as the directory of PCAP data to be processed.
2. set the variable word_dir and word_name as the storage directory of pre-training daraset.
3. set the variable output_split_path and pcap_output_path. The pcap_output_path indicates the storage directory where the pcapng format of PCAP data is converted to pcap format. The output_split_path represents the storage directory for PCAP data slicing into session format.

Finally, you can gnerate pre-training corpus by following the completion of PCAP data processing.

```
python3 pre-process/main.py
```

#### Processing the pre-trained corpus

```
python3 preprocess.py   --corpus_path corpora/traffic.txt \
                        --vocab_path models/encryptd_vocab.txt \
                        --dataset_path distributed/dataset.pt \
                        --processes_num 8 \
                        --data_processor lm

```

### Data Preprocessing for Traffic Understanding Tasks

```
python3 pre-process/input_generation_understanding.py   --pcap_path "data/pcap/" \
                                                        --dataset_dir "data/understanding/datasets/" \
                                                        --class_num 17 \
                                                        --middle_save_path "data/understanding/result/" \
                                                        --random_seed 01
```

### Data Preprocessing for Traffic Generation Tasks


```
python3 pre-process/input_generation_generation.py  --pcap_path "data/pcap/" \
                                                    --dataset_dir "data/generation/datasets/" \
                                                    --class_num 17 \
                                                    --middle_save_path "data/generation/result/" \
                                                    --random_seed 01
```


## Model Pre-training

You can use NetGPT directly by downloading the [pre-trained NetGPT model](https://drive.google.com/file/d/1GNbWtVgrG9XcuApgkSl1hDRTsDXqm12R/view?usp=drive_link), or pre-training NetGPT on your own corpus.


```
python3 pretrain.py   --dataset_path distributed/dataset.pt \
                      --vocab_path models/encryptd_vocab.txt \
                      --config_path models/gpt2/config.json \
                      --output_model_path pretrained_model.bin \
                      --world_size 8 \
                      --gpu_ranks 0 1 2 3 4 5 6 7 \
                      --learning_rate 1e-4 \
                      --data_processor lm \
                      --embedding word pos \
                      --remove_embedding_layernorm \
                      --encoder transformer \
                      --mask causal \
                      --layernorm_positioning pre \
                      --target lm \
                      --tie_weights
```

## Citation

```
@article{meng2023netgpt,
  title={Netgpt: Generative pretrained transformer for network traffic},
  author={Meng, Xuying and Lin, Chungang and Wang, Yequan and Zhang, Yujun},
  journal={arXiv preprint arXiv:2304.09513},
  year={2023}
}
```
