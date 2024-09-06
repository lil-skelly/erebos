# erebos
Fractionated Loader for Linux LKMs

## How does it work
Erebos consists of a server and a client (the loader itself).
The basic concept of erebos, is that the server will stage encrypted blobs of the loaded kernel module object file which the loader will download in a random order, decrypt and assemble them into the original LKM. Finally it will load it to the running kernel.

As opposed to the fractionated cavity loader for windows executables presented in [VXUG Black Mass I 2022](https://samples.vx-underground.org/Papers/Other/VXUG%20Zines/2022-11-13%20-%20Black%20Mass%20Halloween%202022.pdf), the loader avoids touching the disk by working with the data in memory.

## Usage
**Server**:
```bash
$ # Create fractions and stage over HTTP
$ python main.py --file <PATH_TO_OBJ_FILE> --output out
$ # Clean fractions using backup system
$ python main.py --output out
```

### Server
The server is accountable for the preparation and staging of the LKM we want to load.
It:
1. takes as an input the object file of our LKM
2. splits it into chunks of a set size
3. encrypts each chunk with a predefined key
4. assigns important metadata to each chunk that will allow the loader to assemble the object file correctly* (see [ordering the chunks](#ordering-the-chunks))
5. writes each chunk to a file
6. stages the different files via HTTP

## Ordering the chunks
Since the loader will download the encrypted chunks/blobs of the LKMs object file in random order,
it is important to have a way to know which place each chunk goes.
To do that we can append some metadata in the start of each chunk, a header.

The header should also have a fixed length, to be easily extracted from the rest of the encrypted data.

**But what?**
There isn't really a specific answer to that but hey, here's an idea:
```
  -[ Fraction Header ]-
.-----------------------.
| uint32_t magic bytes  |
| uint32_t index        |
| char iv[16]           |
| uint32_t crc          |
'-----------------------'
```
- 4 magic bytes, to ensure we are actually dealing with a header 
- the index of the chunk
- the IV (initialization vector) the chunk was encrypted with
- a CRC32 checksum of the header **and** the encrypted data

Leaves us with a 28-byte header containing precious information.
