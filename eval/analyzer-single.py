#!/usr/bin/env python3

from numpy import void
from typing import List, Tuple
from sklearn.metrics import roc_curve, auc, accuracy_score, f1_score
from sklearn.metrics import precision_score, recall_score, precision_recall_curve, fbeta_score
import json
import os
import math
import argparse
import pandas as pd
import matplotlib.pyplot as plt


def roc_action(label: List[int], score: List[float]) -> void:
    fpr, tpr, _ = roc_curve(label, score)
    roc_auc     = auc(fpr, tpr)

    plt.figure()
    plt.plot(fpr, tpr, color='firebrick', lw=1.5, label=f'AUC: {roc_auc:7.6f}')
    plt.plot([0, 1], [0, 1], color='royalblue', lw=1, linestyle='--')
    plt.xlim([-0.02, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('FPR')
    plt.ylabel('TPR')
    plt.title(f'{args.target} RoC')
    plt.legend(loc="lower right")

    if not os.path.exists('./figure/'):
        os.mkdir('./figure/')
    if not os.path.exists(f'./figure/{class_name}'):
        os.mkdir(f'./figure/{class_name}/')
    if not os.path.exists(f'./figure/{class_name}/{target}'):
        os.mkdir(f'./figure/{class_name}/{target}')

    plt.savefig(f'./figure/{class_name}/{target}/{file_name}-auc-roc.png')

    deta        = 1
    deta_fpr    = 1
    deta_tpr    = 1

    err     = 0
    r_fpr   = 0
    r_tpr   = 0

    for a, b in zip(fpr, tpr):
        d = math.fabs((1 - a) - b)
        if d < deta:
            deta = d
            err = a

        d = math.fabs(a - 0.1)
        if d < deta_fpr:
            deta_fpr = d
            r_tpr = b

        d = math.fabs(b - 0.9)
        if d < deta_tpr:
            deta_tpr = d
            r_fpr = a

    print(f"[{class_name}-{args.target}]")
    print(f"TPR     = {r_tpr:7.6f} (FPR=0.1)")
    print(f"FPR     = {r_fpr:7.6f} (TPR=0.9)")
    print(f"AU-ROC  = {roc_auc:7.6f}")
    print(f"EER     = {err:7.6f}")

    if not os.path.exists('./metrics/'):
        os.mkdir('./metrics/')
    if not os.path.exists(f'./metrics/{class_name}'):
        os.mkdir(f'./metrics/{class_name}/')
    if not os.path.exists(f'./metrics/{class_name}/{target}'):
        os.mkdir(f'./metrics/{class_name}/{target}')

    f = open(f'./metrics/{class_name}/{target}/{file_name}-roc.txt', 'a+')
    f.write(f'[{class_name}-{target}]\n')
    f.write(f'TPR     = {r_tpr:7.6f} (FPR=0.1)\n')
    f.write(f'FPR     = {r_fpr:7.6f} (TPR=0.9)\n')
    f.write(f'AU-ROC  = {roc_auc:7.6f}\n')
    f.write(f'EER     = {err:7.6f}\n')

def f_action(label: List[int], score: List[float]) -> void:
    judge = [1 if sc > water_line else 0 for sc in score]

    f1  = f1_score(label, judge, average='macro')
    pre = precision_score(label, judge, average='macro')
    rec = recall_score(label, judge, average='macro')
    acc = accuracy_score(label, judge)
    f2  = fbeta_score(label, judge, average='macro', beta=2)

    fpr, tpr, thresholds = roc_curve(label, judge)

    p, r, _ = precision_recall_curve(label, judge)
    pr_auc  = auc(p, r)

    plt.figure()
    plt.plot(p, r, color='firebrick', lw=1.5, label=f'AUC: {pr_auc:7.6f}')
    plt.plot([0, 1], [0, 1], color='royalblue', lw=1, linestyle='--')
    plt.xlim([-0.02, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('Precision')
    plt.ylabel('Recall')
    plt.title(f'{args.target} RoC')
    plt.legend(loc="lower right")

    if not os.path.exists('./figure/'):
        os.mkdir('./figure/')
    if not os.path.exists(f'./figure/{class_name}'):
        os.mkdir(f'./figure/{class_name}/')
    if not os.path.exists(f'./figure/{class_name}/{target}'):
        os.mkdir(f'./figure/{class_name}/{target}')

    plt.savefig(f'./figure/{class_name}/{target}/{file_name}-auc-prc.png')

    print(f'F1-score    = {f1:7.6f}')
    print(f'F2-score    = {f2:7.6f}')
    print(f'Precision   = {pre:7.6f}')
    print(f'Recall      = {rec:7.6f}')
    print(f'AU_PRC      = {pr_auc:7.6f}')
    print(f'Accuracy    = {acc:7.6f}')
    print(f'TPR         = {tpr[1]:7.6f}')
    print(f'FPR         = {fpr[1]:7.6f}')

    n_FP = 0
    n_FN = 0

    for a, b in zip(label, judge):
        if a == 1 and b == 0:
            n_FN += 1
        if a == 0 and b == 1:
            n_FP += 1

    print(f'FN = {n_FN}')
    print(f'FP = {n_FP}')

    if not os.path.exists('./metrics/'):
        os.mkdir('./metrics/')
    if not os.path.exists(f'./metrics/{class_name}'):
        os.mkdir(f'./metrics/{class_name}/')
    if not os.path.exists(f'./metrics/{class_name}/{target}'):
        os.mkdir(f'./metrics/{class_name}/{target}')

    f = open(f'./metrics/{class_name}/{target}/{file_name}-prc.txt', 'a+')
    f.write(f'[{dataset}-{target}]\n')
    f.write(f'F1-score  = {f1:7.6f}\n')
    f.write(f'F2-score  = {f2:7.6f}\n')
    f.write(f'Precision = {pre:7.6f}\n')
    f.write(f'Recall    = {rec:7.6f}\n')
    f.write(f'AU_PRC    = {pr_auc:7.6f}\n')
    f.write(f'Accuracy  = {acc:7.6f}\n')
    f.write(f'TPR       = {tpr[1]:7.6f}\n')
    f.write(f'FPR       = {fpr[1]:7.6f}\n')
    f.write(f'FN        = {n_FN}\n')
    f.write(f'FP        = {n_FP}\n')

def analyze_result(label: List[int], score: List[float]) -> bool:
    roc_action(label, score)
    f_action(label, score)
    return True

def get_result_from_file(addr: str) -> Tuple[List[int], List[float]]:
    label       = []
    score       = []

    df = pd.read_csv(f'{addr}.csv')
    label.extend(df['label'].tolist())
    score.extend(df['loss'].tolist())

    print(f'Trace size: {len(label)}')
    return label, score

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--dataset', type=str, help='Cur dataset.')
    parser.add_argument('-t', '--target', type=str, help='Cur attack.')
    parser.add_argument('-f', '--file_name', type=str, help='File name.')

    args = parser.parse_args()

    if not os.path.exists(args.config):
        exit(-1)

    water_line  = 11

    with open(args.config, 'r') as f:
        configd = json.load(f)
        for k,v in configd.items():
            if args.dataset in k:
                if args.target in v:
                    dataset     = args.dataset
                    class_name  = k
                    target      = args.target
                    file_name   = args.file_name
                    break

    analyze_result(*get_result_from_file(f"data/{args.dataset}/{args.target}/{args.file_name}"))
