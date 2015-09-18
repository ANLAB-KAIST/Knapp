#!/bin/bash
rm -f knapp-mic && make -f Makefile.mic -j 4
sudo scp knapp-mic mic0:~/
