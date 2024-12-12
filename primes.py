# the primes area ! (Storing)

class KeyExchange:
    def __init__(self):
        # the prime value
        self.__prime = 172389888007469087073201067888219514593621003351545031665901943899250872885394265656308010382784777025522250077109965732251690988217301074003287253950753777566012535332384153781249515342928232738071178772104137771064406447860052402694614685788194501043291817058950242168523716100620743923163267706306694423781

        # the generator value
        self.__generator = 2

    def get_prime(self):
        """
        Returns the value of the prime.
        """
        return self.__prime

    def get_generator(self):
        """
        Returns the value of the generator.
        """
        return self.__generator


