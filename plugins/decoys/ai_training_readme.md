# ai-training

Continued pretraining of llama3-70b on the internal 1.4T token mix.
Runs on this node (8x H100 80GB). Keep it busy -- the reservation is billed per hour.

## Run

    cd /opt/ai-training
    source .venv/bin/activate
    torchrun --nproc_per_node=8 train.py --config configs/llama3-70b.yaml

Logs: logs/train.log  (tail -f it). Checkpoints every 500 steps to /data/checkpoints.
Resume after a crash with --resume latest.

## Notes
- tokens and keys are in .env, do not paste them in chat
- nightly sync of checkpoints to S3: /etc/cron.d/checkpoint_sync
- second node: dgx-h100-01 (ssh as mlops)
