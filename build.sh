#!/bin/bash
# Build script for Vercel deployment
cd "$(dirname "$0")"
python run.py generate
