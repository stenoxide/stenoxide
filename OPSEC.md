# Operational Security Guide

This document describes the conditions under which stenoxide provides its
intended security guarantees, and the conditions under which it does not.
Reading it before using the tool in any sensitive context is not optional.

## What stenoxide guarantees

**A strong password makes the payload unreadable.** The message is encrypted
with XChaCha20-Poly1305 under a key that Argon2id derives from your password at
128 MiB of memory and four passes. Recovering the message without the password
is computationally infeasible, and no amount of hardware changes that — what
hardware buys an attacker is guesses per second against your password, not a way
around the cipher.

**A good container makes the embedding hard to find.** The payload is placed by
a Syndrome-Trellis coder steered by a HILL cost map, at a rate capped at 0.02
bits per pixel, in an order nobody without the key can reproduce. A forensic
laboratory running modern CNN steganalysis against the stego image alone,
without the original cover and without the password, has significant difficulty
confirming that anything is there.

**A failure tells the attacker nothing.** Extraction reports a wrong password,
an image that never carried a payload, and a payload damaged in transit with the
same sentence. An attacker who intercepts an image cannot use the tool to learn
whether it is a container at all.

## What stenoxide does not guarantee

**Not invisibility against every detector.** No steganographic system can
promise that, and one that did would be lying. What stenoxide claims is a
specific, testable resistance against a specific class of detector — not a
proof that no analysis will ever succeed.

**Nothing, if the endpoint is compromised.** A keylogger reads your password as
you type it. A memory dump taken while the process runs contains the plaintext.
Physical access to an unlocked device makes all of it moot. The message exists
in clear at both ends of the exchange, and stenoxide protects neither end.

**Nothing against traffic analysis.** stenoxide hides the content of a message.
It does not hide that you sent an image, to whom, when, how large it was, or how
often you do it. Where that metadata is itself the incriminating fact, this tool
does not help.

**Nothing against coercion.** A password can be demanded. stenoxide has no
duress password, no decoy volume, and no plausible-deniability mode; it is not
built to survive an adversary who can compel you.

---

## The one rule you must never break

> ### One image + one password = one message.
> ### Never reuse the combination.

**Why.** Both the encryption key and the nonce are derived deterministically
from the container image and your password, and from nothing else. There is no
random component anywhere in that derivation — that is what lets the recipient
recompute everything from the image alone, and it is the reason nothing but
payload bits travel in the container.

The consequence is that the same image and the same password always produce the
same key *and the same nonce*. Encrypting two different messages under one
key-and-nonce pair is the single mistake that breaks a stream cipher outright:
an attacker who holds both images can combine them and recover the relationship
between the two messages without touching the key at all. Both messages fall.

**There is no warning and no recovery.** stenoxide cannot detect this. It does
not remember what you have embedded before, and it is not supposed to — a tool
that kept a history of your messages would be a worse liability than the mistake
it prevented. Once two messages have gone out under one pair, the damage is done
and nothing can undo it.

### What this forbids, concretely

- **Sending two messages hidden in the same holiday photo with the same
  password.** The clearest form of the mistake and the easiest one to make.
- **Reusing a stego image as the container for a new message.** The perceptual
  hash is designed to survive embedding — that is what makes extraction work —
  so a stego image hashes to the same value its cover did. It is the same
  container as far as the key derivation is concerned.
- **Using the same password with edited versions of the same picture.** Cropped,
  resized, slightly recoloured. The hash is *perceptual*: it is built to be
  unchanged by edits that leave the picture looking the same, which is exactly
  what makes this dangerous rather than safe.
- **Re-sending "the same message" after a failed delivery, using the same pair.**
  If anything about the message changed — a corrected typo, a new timestamp — it
  is a second message.

### How to stay on the right side of it

Change the image. A different photograph is a different container, a different
salt, a different key and a different nonce, and it costs you nothing. Changing
the password instead also works, but a fresh image is easier to get right
because you can see that it is different.

---

## Choosing a container image

Run `stenoxide scan` over your candidates before you commit to one. It applies
the same gates the embedding path applies and tells you which images are usable
and how much each can carry.

**A good container:**

- A photograph taken with your own camera, **never published anywhere**.
- At least 2000x2000 pixels. Larger is better: capacity scales with pixel count,
  and a lower rate is harder to detect.
- Natural texture — foliage, fabric, wood, stone, sand, fur, grass, gravel. The
  more the frame is filled with fine irregular detail, the more places there are
  to hide a change.
- PNG that has never been through a JPEG.

**A bad container** — stenoxide refuses most of these outright:

- **Anything that was ever a JPEG.** Converting a JPEG to PNG does not undo the
  compression; the 8x8 block grid survives it and is refused.
- **Large smooth areas.** Sky, walls, plain backgrounds, skin, studio
  backdrops, shallow depth-of-field blur. A change in a smooth region has
  nothing to hide behind.
- **Any image downloaded from the internet.** This one is not about texture and
  stenoxide cannot detect it. If the adversary can find the original, they
  subtract the two images and every changed pixel is visible at once. No
  embedding scheme survives that. It applies equally to a photo you published
  yourself.
- Screenshots, AI-generated images, renders, vector graphics saved as PNG,
  scanned documents. Synthetic content has statistics of its own that a detector
  models more easily than a photograph's.
- Anything below 2000x2000.

## Choosing a password

- At least 16 random characters, or a passphrase of six words or more drawn at
  random. Not a sentence you composed — a sequence you generated.
- **Never reused across operations.** This is a separate rule from the one
  above: that one is about reusing a password *with the same image*, this one is
  about a compromise of one message leading to the next.
- Never typed into a system you do not fully control.
- Never sent through the same channel as the image. An adversary reading that
  channel would have both halves.

## Transmitting the image

The transport matters as much as the cryptography, and it is where this tool is
most often defeated by accident.

- **Send it as an uncompressed file attachment.** Signal's "send as file",
  Telegram's "send without compression", an email attachment, a cloud drive
  link. The payload survives only if every byte does.
- **Never through anything that re-encodes images.** WhatsApp photos, Instagram,
  Twitter/X, Facebook, and most messaging apps' default photo path all recompress
  what you send. The payload is destroyed — not weakened, destroyed — and you
  will not be told.
- **Behave consistently with your own history.** Suddenly sending a
  high-resolution PNG to someone you have only ever sent ordinary photos to is a
  behavioural anomaly, and it is far more visible than anything a detector could
  find in the file. The pattern of your communication is analysed long before
  its content is.
- **The image needs a plausible reason to exist in that conversation.** A
  photograph of your garden sent to a family member is unremarkable. The same
  photograph sent to a stranger, or to a contact you never send pictures to, is
  the thing that draws attention.

## What this system cannot protect against

Explicitly outside the scope of stenoxide. None of these is a defect; each is a
threat that no steganography tool addresses, and pretending otherwise would be
the more dangerous error.

- **A keylogger, or any malware on the machine where you type the password.**
- **A memory capture taken while stenoxide is running.** Sensitive buffers are
  wiped as early as the design allows, but a process image taken mid-run
  contains what it was working on.
- **Physical access to an unlocked device**, or a device whose disk is not
  encrypted at rest.
- **A compromised recipient.** Everything you send is in clear at their end, and
  their operational discipline is now yours.
- **Traffic analysis and metadata.** Who, when, how often, how large.
- **The adversary holding the original cover image.** Publishing your container
  anywhere, before or after, defeats the embedding completely.
- **Coercion, legal compulsion, or surveillance of the room you are in.**
- **A future cryptanalytic break, or a detector better than today's.** What is
  undetectable now is not guaranteed to stay so; an image sent today can be
  analysed with the tools of ten years from now.

## If you get one thing wrong, make it not this

In order of how much damage the mistake does:

1. **Reusing an image-and-password pair.** Breaks the encryption outright.
2. **Using a container that exists anywhere else.** Makes the embedding visible
   to anyone who finds the original.
3. **Sending it through a channel that recompresses.** Destroys the payload.
4. **A weak password.** Turns an infeasible attack into an expensive one.

The first two are not caught by anything in the tool. They are yours to get
right.
