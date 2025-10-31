from pw_analyzer import brute_force_simulator
found, attempts, match = brute_force_simulator(
    "thisisaverylongpassword",
    "abcdefghijklmnopqrstuvwxyz0123456789",
    max_attempts=100000000,
    max_len=6,
    max_seconds=1.0
)
print("found:", found, "attempts:", attempts, "match:", match)
