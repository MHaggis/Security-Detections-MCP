# Public CQL transport regression fixture

`cql-blocked-batch.json.gz` contains the first 100 filename-sorted YAML rules in
[ByteRay-Labs/Query-Hub](https://github.com/ByteRay-Labs/Query-Hub/tree/a453fcb09118894840a4e00b0db0f9807ba8441d/queries),
at revision `a453fcb09118894840a4e00b0db0f9807ba8441d`, parsed by this project's
CrowdStrike parser. `file_path` is omitted and `references` maps to `refs`, matching
the seed payload. The parser input prefix was `../../sources/cql-hub/queries`;
this matters because the existing parser includes the path when deriving IDs.
Rule authors remain attributed in each record and the embedded original YAML.

The upstream README declares the queries MIT licensed, maintained by ByteRay and
community contributors. The fixture is compressed to keep the repository small;
tests decompress it without modifying detection content.

Decoded JSON: 562877 bytes, SHA-256
`ee14eba97ca988b9abd433e898cb52352ad826b62f221f118c2643284fd75c2c`.

On 2026-11-04 this exact JSON body returned Cloudflare HTML403 from the owned
project's direct detections endpoint (Ray `a55592cc981a538a-DEN`). Anonymous
benign controls before/after, another CQL batch, Jamf rules and a larger benign
body reached the expected JSON permission denial. All six probes were denied;
no production writes were made. Public API keys are not stored in this fixture.

Tests compare every original mapped field after both RPC ingestion and the
actual SQLite seed CLI, in addition to source identity and edge integrity.

## MIT license notice

Copyright ByteRay and Query-Hub contributors.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
