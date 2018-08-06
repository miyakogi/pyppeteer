#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Chromium download module."""

from io import BytesIO
import logging
import os
from pathlib import Path
import stat
import sys
from zipfile import ZipFile

import urllib3
from tqdm import tqdm

from pyppeteer import __chromimum_revision__, __pyppeteer_home__

logger = logging.getLogger(__name__)

DOWNLOADS_FOLDER = Path(__pyppeteer_home__) / 'local-chromium'
DEFAULT_DOWNLOAD_HOST = 'https://storage.googleapis.com'
ALTERNATIVE_DOWNLOAD_HOST = 'https://npm.taobao.org/mirrors'
DOWNLOAD_HOST = os.environ.get(
    'PYPPETEER_DOWNLOAD_HOST', DEFAULT_DOWNLOAD_HOST)

REVISION = os.environ.get(
    'PYPPETEER_CHROMIUM_REVISION', __chromimum_revision__)

chromiumExecutable = {
    'linux': DOWNLOADS_FOLDER / REVISION / 'chrome-linux' / 'chrome',
    'mac': (DOWNLOADS_FOLDER / REVISION / 'chrome-mac' / 'Chromium.app' /
            'Contents' / 'MacOS' / 'Chromium'),
    'win32': DOWNLOADS_FOLDER / REVISION / 'chrome-win32' / 'chrome.exe',
    'win64': DOWNLOADS_FOLDER / REVISION / 'chrome-win32' / 'chrome.exe',
}

def current_platform() -> str:
    """Get current platform name by short string."""
    if sys.platform.startswith('linux'):
        return 'linux'
    elif sys.platform.startswith('darwin'):
        return 'mac'
    elif (sys.platform.startswith('win') or
          sys.platform.startswith('msys') or
          sys.platform.startswith('cyg')):
        if sys.maxsize > 2 ** 31 - 1:
            return 'win64'
        return 'win32'
    raise OSError('Unsupported platform: ' + sys.platform)


def get_download_url(base_download_host) -> (dict, dict):
    DOWNLOAD_HOST = os.environ.get(
        'PYPPETEER_DOWNLOAD_HOST', base_download_host)
    BASE_URL = f'{DOWNLOAD_HOST}/chromium-browser-snapshots'
    downloadURLs = {
        'linux': f'{BASE_URL}/Linux_x64/{REVISION}/chrome-linux.zip',
        'mac': f'{BASE_URL}/Mac/{REVISION}/chrome-mac.zip',
        'win32': f'{BASE_URL}/Win/{REVISION}/chrome-win32.zip',
        'win64': f'{BASE_URL}/Win_x64/{REVISION}/chrome-win32.zip',
    }
    return downloadURLs


def get_url(base_download_host) -> str:
    """Get chromium download url."""
    downloadURLs = get_download_url(base_download_host)
    return downloadURLs[current_platform()]


def download_zip(url: str) -> BytesIO:
    """Download data from url."""
    logger.warning('start chromium download.\n'
                   'Download may take a few minutes.')

    # disable warnings so that we don't need a cert.
    # see https://urllib3.readthedocs.io/en/latest/advanced-usage.html for more
    urllib3.disable_warnings()

    with urllib3.PoolManager() as http:
        # Get data from url.
        # set preload_content=False means using stream later.
        data = http.request('GET', url, preload_content=False)

        try:
            total_length = int(data.headers['content-length'])
        except (KeyError, ValueError, AttributeError):
            total_length = 0

        process_bar = tqdm(total=total_length)

        # 10 * 1024
        _data = BytesIO()
        for chunk in data.stream(10240):
            _data.write(chunk)
            process_bar.update(len(chunk))

    logger.warning('\nchromium download done.')
    return _data


def extract_zip(data: BytesIO, path: Path) -> None:
    """Extract zipped data to path."""
    # On mac zipfile module cannot extract correctly, so use unzip instead.
    if current_platform() == 'mac':
        import subprocess
        import shutil
        zip_path = path / 'chrome.zip'
        if not path.exists():
            path.mkdir(parents=True)
        with zip_path.open('wb') as f:
            f.write(data.getvalue())
        if not shutil.which('unzip'):
            raise OSError('Failed to automatically extract chrome.zip.'
                          f'Please unzip {zip_path} manually.')
        subprocess.run(['unzip', str(zip_path)], cwd=str(path))
        if chromium_excutable().exists() and zip_path.exists():
            zip_path.unlink()
    else:
        with ZipFile(data) as zf:
            zf.extractall(str(path))
    exec_path = chromium_excutable()
    if not exec_path.exists():
        raise IOError('Failed to extract chromium.')
    exec_path.chmod(exec_path.stat().st_mode | stat.S_IXOTH | stat.S_IXGRP |
                    stat.S_IXUSR)
    logger.warning(f'chromium extracted to: {path}')


def download_chromium() -> None:
    """Downlaod and extract chrmoium."""
    try:
        zipped = download_zip(get_url(DEFAULT_DOWNLOAD_HOST))
    except Exception as e:
        print('Default mirror URL is invalid!\n'
              'Switching to alternative mirror.')
        zipped = download_zip(get_url(ALTERNATIVE_DOWNLOAD_HOST))
    finally:
        extract_zip(zipped, DOWNLOADS_FOLDER / REVISION)


def chromium_excutable() -> Path:
    """Get path of the chromium executable."""
    return chromiumExecutable[current_platform()]


def check_chromium() -> bool:
    """Check if chromium is placed at correct path."""
    return chromium_excutable().exists()
