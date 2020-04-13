# imageIO
Simple, pure Python 3, FUSE-based rootFS image read-only access. Currently supported rootFS images:
- SquashFS
- JFFS2

## Usage
- Clone this repo
- Create python local environment: `cd imageio && python3 -m venv env && source env/bin/activate`
- Install dependencies: `pip install -r requirements.txt`
- Mount rootFS image: `python fuse_driver.py -m [mount_dir] [path_to_rootFS]`
  - To get debug info: `python fuse_driver.py -d -m [mount_dir] [path_to_rootFS]`


## Examples
- `./examples/dumpFile.py` gives an example how to extract a file from an image without mounting.


Limited testing was done on LZO, LZMA, XZ compressed images.

Pull requests, suggestions are welcome.
