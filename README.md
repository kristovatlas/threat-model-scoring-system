# weight-comparison
Tools for comparing proposed changes to how threat model criteria are weighted. Our threat model can be found here:
https://github.com/OpenBitcoinPrivacyProject/wallet-ratings/

## Requirements

* Tested on Python 2.7
* jsonschema `pip install jsonschema`

## Example

What if we vastly elevated the importance of attacks performed by a wallet provider?

`python app.py data/threat_model_2nd_edition.json test/threat_model_2nd_edition_mega_wallet_provider.json`

```
Change #1:
    Was: V A 2 a = 0.53 * II A 3 a
    Now: V A 2 a = 5.27 * II A 3 a
Change #2:
    Was: V A 2 a = 0.56 * I A 1 b
    Now: V A 2 a = 5.58 * I A 1 b
Change #3:
    Was: V A 2 a = 0.26 * III B 1 a
    Now: V A 2 a = 2.60 * III B 1 a
...
```
