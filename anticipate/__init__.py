"""Anticipation mode: defensive source review of a released version that was later fixed upstream.

Reads public source code at a vulnerable release, asks the confined patch model to find and fix a
defect of a given class (without being told which advisory), then checks the result mechanically
and compares it with the official upstream fix. No server is run and no traffic is sent.
"""
