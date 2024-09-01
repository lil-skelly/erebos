# erebos
Fractionated Cavity Loader for Linux LKMs

## How does it work
Erebos will consist of a server and a client (the loader itself).
The basic concept of the loader is that the server will stage encrypted blobs of data which the loader will download in a random order, decrypt them and assemble the original object. 
Finally it will load it to the running kernel.

### Server
The server is accountable for the preparation and staging of the LKM we want to load.
It will:
1. take as an input the object file of our LKM
2. split it into chunks of a set size (ex. 1024 bytes)
3. encrypt each chunk with a predefined key (ex. AES-256)
4. assign important metadata to each chunk that will allow the loader to assemble the object file correctly* (see [ordering the chunks](#ordering-the-chunks))
5. write each chunk to a file
6. stage the different files via HTTP

## Ordering the chunks
Since the loader will download the encrypted chunks/blobs of the LKMs object file in random order,
it is important to have a way to know which place each chunk goes.
To do that we can append some metadata in the start of each chunk, a header.

The header should also have a fixed length, to be easily extracted from the rest of the encrypted data.

**But what?**
There isn't really a specific answer to that but hey, here's an idea:
Each header will contain:
- 4 magic bytes*, to ensure we are actually dealing with a header
- the index of the chunk
- the IV (initialization vector) the chunk was encrypted with
- a CRC32 checksum/hash of the header and the encrypted data

\* Why use 3 when with 4 you get 0xdeadbeef ;)
