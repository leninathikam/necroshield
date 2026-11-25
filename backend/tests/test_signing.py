"""Signed evidence. The pure-Python verifier is checked against RFC 8032's published vectors and, where
the `cryptography` package exists (CI), against an independent implementation."""

import base64
import copy
import hashlib
import json
import subprocess
import sys

import pytest

from necroshield.catalog import REGISTRY
from necroshield.metrics import BUNDLE_FORMAT, summarize
from necroshield.runner import run_pair
from tests.conftest import VERIFIER_PATH

RFC8032 = [  # (seed, message, public key, signature): RFC 8032 section 7.1, tests 1 and 2
    ("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "",
     "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
     "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"),
    ("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "72",
     "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
     "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"),
]


def _compress(v, point):
    z = pow(point[2], v._P - 2, v._P)
    return int.to_bytes((point[1] * z % v._P) | ((point[0] * z % v._P & 1) << 255), 32, "little")


def ref_keypair_and_sign(v, seed: bytes, message: bytes):
    """Reference signer for tests only (RFC 8032), built from the verifier's own group arithmetic."""
    h = hashlib.sha512(seed).digest()
    a = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    public = _compress(v, v._mul(a, v._G))
    r = int.from_bytes(hashlib.sha512(h[32:] + message).digest(), "little") % v._Q
    big_r = _compress(v, v._mul(r, v._G))
    k = int.from_bytes(hashlib.sha512(big_r + public + message).digest(), "little") % v._Q
    return public, big_r + int.to_bytes((r + k * a) % v._Q, 32, "little")


class Keys:
    def __init__(self, v, seed_byte: int):
        self.v, self.seed = v, bytes([seed_byte]) * 32
        self.public, _ = ref_keypair_and_sign(v, self.seed, b"")
        self.key_id = hashlib.sha256(self.public).hexdigest()[:16]

    def sign(self, payload, signed_at="2026-11-24T20:00:00+00:00"):
        message = self.v.signed_message(self.key_id, signed_at, payload)
        _, sig = ref_keypair_and_sign(self.v, self.seed, message)
        return {"format": self.v.SIGNED_FORMAT, "payload": payload,
                "signature": {"alg": "ed25519", "key_id": self.key_id, "signed_at": signed_at,
                              "sig": base64.b64encode(sig).decode()}}


@pytest.fixture(scope="module")
def keys(verifier):
    return Keys(verifier, 7), Keys(verifier, 9)


def bundle(pairs=None):
    pairs = pairs or [json.loads(json.dumps(run_pair(s).export())) for s in REGISTRY.values()]
    return {"format": BUNDLE_FORMAT, "summary": summarize(pairs), "pairs": pairs}


@pytest.fixture(scope="module")
def good_bundle():
    return bundle()


def pins():
    return {s.scenario_id: {"scenario_digest": s.digest(), "policy_digest": s.policy.digest()} for s in REGISTRY.values()}


@pytest.mark.parametrize("seed, message, public, signature", RFC8032)
def test_rfc8032_published_vectors(verifier, seed, message, public, signature):
    pub, msg, sig = bytes.fromhex(public), bytes.fromhex(message), bytes.fromhex(signature)
    assert verifier.ed25519_verify(pub, msg, sig)
    assert ref_keypair_and_sign(verifier, bytes.fromhex(seed), msg) == (pub, sig)  # the reference signer agrees with the RFC
    assert not verifier.ed25519_verify(pub, msg + b"x", sig)
    flipped = bytes([sig[0] ^ 1]) + sig[1:]
    assert not verifier.ed25519_verify(pub, msg, flipped)


def test_malformed_signatures_and_keys_are_rejected(verifier):
    pub, msg, sig = (bytes.fromhex(x) for x in (RFC8032[1][2], RFC8032[1][1], RFC8032[1][3]))
    s_plus_q = int.from_bytes(sig[32:], "little") + verifier._Q
    assert not verifier.ed25519_verify(pub, msg, sig[:32] + s_plus_q.to_bytes(32, "little"))  # non-canonical S
    assert not verifier.ed25519_verify(pub, msg, sig[:-1]) and not verifier.ed25519_verify(pub[:-1], msg, sig)
    assert not verifier.ed25519_verify(b"\xff" * 32, msg, sig) and not verifier.ed25519_verify(pub, msg, b"\xff" * 64)


def test_signed_bundle_verifies_with_the_trusted_key(verifier, keys, good_bundle):
    trusted, _ = keys
    assert verifier.verify_signed(trusted.sign(good_bundle), trusted.public, pins()) == []


def test_altered_payload_breaks_the_signature(verifier, keys, good_bundle):
    trusted, _ = keys
    doc = trusted.sign(copy.deepcopy(good_bundle))
    assert doc["payload"]["summary"]["attack_success"]["protected"]["numerator"] == 0
    doc["payload"]["summary"]["attack_success"]["protected"]["numerator"] = 1  # a real change
    assert verifier.verify_signed(doc, trusted.public) == ["signature does not match the payload"]


def test_substituted_policy_breaks_the_signature(verifier, keys, good_bundle):
    trusted, _ = keys
    doc = trusted.sign(copy.deepcopy(good_bundle))
    doc["payload"]["pairs"][0]["policy"]["grants"].append(
        {"grant_id": "g-x", "tool": "send_message", "allowed_args": {"to": None, "attach": None}})
    assert verifier.verify_signed(doc, trusted.public) == ["signature does not match the payload"]


def test_forged_content_re_signed_with_the_attackers_key_is_rejected(verifier, keys, good_bundle):
    trusted, attacker = keys
    forged = copy.deepcopy(good_bundle)
    forged["summary"]["attack_success"]["protected"]["numerator"] = 6
    assert verifier.verify_signed(attacker.sign(forged), trusted.public) == [
        "signature was made by a different key than the trusted public key"]


def test_a_signature_cannot_be_moved_to_another_payload(verifier, keys, good_bundle):
    trusted, _ = keys
    doc = trusted.sign(good_bundle)
    other = trusted.sign(bundle([good_bundle["pairs"][0]]))
    doc["signature"] = other["signature"]
    assert verifier.verify_signed(doc, trusted.public) == ["signature does not match the payload"]


def test_claimed_time_and_key_id_are_bound(verifier, keys, good_bundle):
    trusted, _ = keys
    doc = trusted.sign(good_bundle)
    later = copy.deepcopy(doc)
    later["signature"]["signed_at"] = "2027-01-01T00:00:00+00:00"
    assert verifier.verify_signed(later, trusted.public) == ["signature does not match the payload"]
    wrong_id = copy.deepcopy(doc)
    wrong_id["signature"]["key_id"] = "0" * 16
    assert verifier.verify_signed(wrong_id, trusted.public)


@pytest.mark.parametrize("mutate", [
    lambda d: d["signature"].update(sig="!!!not base64"),
    lambda d: d["signature"].update(sig=base64.b64encode(b"short").decode()),
    lambda d: d["signature"].update(alg="rsa"),
    lambda d: d["signature"].pop("signed_at"),
    lambda d: d.update(extra=1),
    lambda d: d.pop("signature"),
    lambda d: d.update(format="necroshield.signed/2"),
])
def test_malformed_signed_documents_are_reported_not_raised(verifier, keys, good_bundle, mutate):
    trusted, _ = keys
    doc = trusted.sign(good_bundle)
    mutate(doc)
    assert verifier.verify_signed(doc, trusted.public)


def test_a_valid_signature_does_not_make_an_invalid_summary_valid(verifier, keys, good_bundle):
    """Signatures prove who vouched for the content, not that the content is right."""
    trusted, _ = keys
    wrong = copy.deepcopy(good_bundle)
    wrong["summary"]["task_completion"]["protected"]["numerator"] = 0
    problems = verifier.verify_signed(trusted.sign(wrong), trusted.public)
    assert problems and all(p.startswith("payload:") for p in problems)
    assert any("summary does not match" in p for p in problems)


def test_a_signed_pair_export_verifies_too(verifier, keys):
    trusted, _ = keys
    pair = json.loads(json.dumps(run_pair(REGISTRY["memory_poisoning"]).export()))
    assert verifier.verify_signed(trusted.sign(pair), trusted.public) == []


def _cli(tmp_path, document, *extra):
    path = tmp_path / "doc.json"
    path.write_text(json.dumps(document))
    return subprocess.run([sys.executable, "-I", "-S", str(VERIFIER_PATH), str(path), *extra], capture_output=True, text=True)


def test_cli_requires_the_key_for_signed_files_and_a_signature_when_a_key_is_given(keys, good_bundle, tmp_path):
    trusted, _ = keys
    signed = trusted.sign(good_bundle)
    ok = _cli(tmp_path, signed, "--public-key", trusted.public.hex())
    assert ok.returncode == 0 and "signature valid for the trusted key" in ok.stdout, ok.stdout + ok.stderr
    no_key = _cli(tmp_path, signed)
    assert no_key.returncode == 1 and "supply the trusted public key" in no_key.stdout
    stripped = _cli(tmp_path, good_bundle, "--public-key", trusted.public.hex())
    assert stripped.returncode == 1 and "carries no signature" in stripped.stdout
    wrong = _cli(tmp_path, signed, "--public-key", keys[1].public.hex())
    assert wrong.returncode == 1 and "different key" in wrong.stdout
    bad_key = _cli(tmp_path, signed, "--public-key", "abc")
    assert bad_key.returncode == 1


def test_private_keys_never_appear_in_the_repository_sources():
    from pathlib import Path
    root = Path(__file__).resolve().parents[2]
    hits = [str(p) for p in list((root / "backend" / "necroshield").rglob("*.py")) + list((root / "frontend").rglob("*.ts*"))
            if "node_modules" not in p.parts and "PRIVATE KEY" in p.read_text(errors="ignore")]
    assert hits == []


# --- needs the `cryptography` package (CI) ------------------------------------------------------

@pytest.fixture
def crypto():
    return pytest.importorskip("cryptography")


def test_pure_python_verifier_accepts_signatures_from_an_independent_implementation(crypto, verifier):
    from necroshield.signing import generate_keypair, signer_from_seed_b64
    seed, public_hex = generate_keypair()
    signer = signer_from_seed_b64(seed)
    assert signer.public.hex() == public_hex
    payload = bundle()
    doc = signer.sign(payload)
    assert verifier.verify_signed(doc, signer.public, pins()) == []
    assert seed not in json.dumps(doc)


def test_signer_describe_publishes_only_the_public_half(crypto):
    from necroshield.signing import generate_keypair, signer_from_seed_b64
    seed, public_hex = generate_keypair()
    info = signer_from_seed_b64(seed).describe()
    assert info["public_key"] == public_hex and seed not in json.dumps(info) and "private" not in json.dumps(info).lower()


@pytest.mark.parametrize("bad", ["", "not base64!!", base64.b64encode(b"short").decode()])
def test_invalid_signing_keys_are_rejected(crypto, bad):
    from necroshield.signing import signer_from_seed_b64
    with pytest.raises(ValueError):
        signer_from_seed_b64(bad)


def test_keygen_and_sign_cli_round_trip(crypto, tmp_path, good_bundle):
    key, signed = tmp_path / "key.b64", tmp_path / "signed.json"
    src = tmp_path / "bundle.json"
    src.write_text(json.dumps(good_bundle))
    out = subprocess.run([sys.executable, "-m", "necroshield", "keygen", "--out", str(key)], capture_output=True, text=True,
                         cwd=VERIFIER_PATH.parents[1] / "backend", check=True).stdout
    public = out.split(": ")[-1].strip()
    assert oct(key.stat().st_mode & 0o777) == "0o600"
    again = subprocess.run([sys.executable, "-m", "necroshield", "keygen", "--out", str(key)], capture_output=True, text=True,
                           cwd=VERIFIER_PATH.parents[1] / "backend")
    assert again.returncode == 1 and "refusing to overwrite" in again.stderr
    backend = VERIFIER_PATH.parents[1] / "backend"
    subprocess.run([sys.executable, "-m", "necroshield", "sign", str(src), "--key-file", str(key), "--out", str(signed)],
                   cwd=backend, check=True, capture_output=True)
    check = subprocess.run([sys.executable, "-I", "-S", str(VERIFIER_PATH), str(signed), "--public-key", public],
                           capture_output=True, text=True)
    assert check.returncode == 0, check.stdout
    forged = json.loads(src.read_text())
    forged["summary"]["scenarios"] = 99
    src.write_text(json.dumps(forged))
    refused = subprocess.run([sys.executable, "-m", "necroshield", "sign", str(src), "--key-file", str(key), "--out",
                              str(tmp_path / "x.json")], cwd=backend, capture_output=True, text=True)
    assert refused.returncode == 1 and "refusing to sign evidence that failed verification" in refused.stderr
