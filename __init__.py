# Copyright 2021 magohole
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# <http://www.apache.org/licenses/LICENSE-2.0>
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from dataclasses import dataclass, field
from functools import partial
from io import BytesIO

bti = partial(int.from_bytes, byteorder="little")
itb = partial(int.to_bytes, byteorder="little", length=2)


@dataclass(kw_only=True)
class RiffChunk:
    cid: bytes = b""
    size: int = 0
    extra: bytes = b""
    offset: int = 0
    hsize: int = 8
    cht: list = field(default_factory=list)
    mod: bool = False
    data: bytes = b""


class RiffPath:
    def __init__(self, top: RiffChunk, parr: list[int]):
        self.etp = top
        self.p: list[int] = parr
        lf = len(parr)
        if lf > 1:
            self.ep = self.get_block(lf - 2)
        else:
            self.ep = top
        self.ebl: RiffChunk = self.get_block(lf - 1)

    def get_block(self, pos: int) -> RiffChunk:
        tp = self.p[: pos + 1]
        nbl = self.etp
        for i in tp:
            nbl = nbl.cht[i]
        return nbl

    def update_path_sz(self, nsz: int) -> None:
        diff = nsz - self.ebl.size
        barr = [self.get_block(bp) for bp in range(len(self.p))]
        barr.insert(0, self.etp)
        for i in barr:
            i.size += diff

    def add_header_size(self, _hsize=8):
        barr = [self.get_block(bp) for bp in range(len(self.p))]
        barr.insert(0, self.etp)
        for i in barr:
            i.size += _hsize

    def set_path_mod(self, boo):
        barr = [self.get_block(bp) for bp in range(len(self.p))]
        barr.insert(0, self.etp)
        for i in barr:
            i.mod = boo


riff_chunk = RiffChunk
riff_path = RiffPath


class __w:
    p = None


def is_riff(fs: BytesIO) -> bool:
    fs.seek(0)

    h = fs.read(4)
    return h == b"RIFF"


def get_chunk(fs: BytesIO, off=0) -> RiffChunk:
    fs.seek(off)
    h = fs.read(4)
    fss = bti(fs.read(4))
    ack = RiffChunk(cid=h, size=fss)
    ack.offset = off + 8
    if h == b"RIFF" or h == b"LIST":
        ack.extra = fs.read(4)
        ack.offset += 4
        ack.hsize += 4
    return ack


def get_riff(fs: BytesIO):
    if not is_riff(fs):
        raise ValueError("Invalid RIFF file")
    off = __w()
    off.p = 0
    return _get_level(fs, off)


def _get_level(
    fs: BytesIO,
    off: __w,
    size: int | None = None,
    parent: RiffChunk | None = None,
):
    if size is None and parent is None:
        p = get_chunk(fs)
        off.p += p.hsize
        _get_level(fs, off, p.size, p)  # Sets .cht
        return p
    roff = 4  # Why 4? Because the extra 4 bytes on the parent ck are included in size
    arr = []

    while roff < size:
        ck = get_chunk(fs, off.p)
        off.p += ck.hsize
        if ck.cid == b"RIFF" or ck.cid == b"LIST":  # Inception
            _get_level(fs, off, ck.size, ck)  # Sets ck.cht
        else:
            off.p += ck.size
        arr.append(ck)
        roff += ck.hsize + ck.size
    parent.cht = arr
    return arr


def get_metadata(fs, l):
    if l.cid != b"LIST" or l.extra != b"INFO":
        raise ValueError("Bad metadata block")
    m = dict()
    for i in l.cht:
        fs.seek(i.offset)
        m[i.cid] = fs.read(i.size)
    return m


def path_to_metadata(pbl, new=False):
    bl = pbl.ebl
    cc: list[int] = []
    for c in range(len(bl.cht)):
        if bl.cht[c].cid == b"LIST" and bl.cht[c].extra == b"INFO":
            cc.append(c)

    if not cc:
        if not new:
            raise ValueError("Metadata block not found")

        nbl = RiffChunk(
            cid=b"LIST",
            size=4,
            hsize=12,
            extra=b"INFO",
            mod=True,
        )
        cc.append(len(pbl.ebl.cht))
        pbl.ebl.cht.append(nbl)
        pbl.add_header_size(_hsize=12)  # 8 in normal cases, here we include size
        pbl.set_path_mod(True)

    return RiffPath(bl, cc)


def set_metadata(bpath: RiffPath, di: dict, nullc=False) -> None:
    bl = bpath.ebl
    if bl.cid != b"LIST" or bl.extra != b"INFO":
        raise ValueError("Bad metadata block")
    arr: list[RiffChunk] = []
    acsz = 0
    for a in di:
        aa = a[:4]
        if len(di[a]) % 2 or nullc:
            di[a] += b"\x00"
        arr.append(
            RiffChunk(
                cid=aa,
                size=len(di[a]),
                mod=True,
                data=di[a],
            )
        )
        acsz += 8 + len(di[a])
    acsz += 4
    bl.mod = True
    bl.cht = arr
    bpath.update_path_sz(acsz)  # chunk.size+=(diff of acsz) for everyone
    bpath.set_path_mod(True)


def save_riff(dest_fs: BytesIO, buff: BytesIO, chunk: RiffChunk):
    dest_fs.write(chunk.cid)
    dest_fs.write(itb(chunk.size, length=4))
    if chunk.mod:
        if chunk.cid == b"RIFF" or chunk.cid == b"LIST":
            if chunk.data is None:
                dest_fs.write(chunk.extra)
                for i in chunk.cht:
                    save_riff(dest_fs, buff, i)
            else:
                dest_fs.write(chunk.data)
        else:
            dest_fs.write(chunk.data)
    else:
        if chunk.cid == b"RIFF" or chunk.cid == b"LIST":
            dest_fs.write(chunk.extra)
            buff.seek(chunk.offset)
            dest_fs.write(buff.read(chunk.size - 4))
        else:
            buff.seek(chunk.offset)
            dest_fs.write(buff.read(chunk.size))
