# import
import random
from cyphers import primes

# Commonly agreed upon prime number and generator value
p = primes.KeyExchange().get_prime()
g = primes.KeyExchange().get_generator()

# Generates a secret value for the client
client_secret_val = random.randint(1, p - 1)

# Generates the public value for the client
client_public_val = pow(g, client_secret_val, p)

# note : pow(a, b, c) = a^b (mod c) = (a^b) % c = pow(a, b) % c



