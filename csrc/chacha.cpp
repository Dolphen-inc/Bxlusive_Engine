#include <cstdint>
#include <vector>
#include <stdexcept>
#include <cstring>

class ChaCha20Engine {
private:
    // RFC 7539 Constant state: "expand 32-byte k"
    static constexpr uint32_t CONSTANTS[4] = {
        0x61707865, 0x3320646e, 0x79203262, 0x6b206574
    };

    // 32-bit left rotation helper
    static inline uint32_t rotl32(uint32_t v, int n) {
        return (v << n) | (v >> (32 - n));
    }

    // Standard Quarter Round primitive
    static inline void quarter_round(uint32_t state[16], int a, int b, int c, int d) {
        state[a] += state[b]; state[d] = rotl32(state[d] ^ state[a], 16);
        state[c] += state[d]; state[b] = rotl32(state[b] ^ state[c], 12);
        state[a] += state[b]; state[d] = rotl32(state[d] ^ state[a], 8);
        state[c] += state[d]; state[b] = rotl32(state[b] ^ state[c], 7);
    }

    // Generates a single 64-byte keystream block
    static std::vector<uint8_t> block(const std::vector<uint8_t>& key, uint32_t counter, const std::vector<uint8_t>& nonce) {
        if (key.size() != 32) {
            throw std::invalid_argument("Key must be exactly 32 bytes (256 bits).");
        }
        if (nonce.size() != 12) {
            throw std::invalid_argument("Nonce must be exactly 12 bytes (96 bits).");
        }

        uint32_t initial_state[16];
        
        // 1. Constants (4 words)
        std::memcpy(&initial_state[0], CONSTANTS, 16);

        // 2. Key (8 words)
        std::memcpy(&initial_state[4], key.data(), 32);

        // 3. Counter (1 word)
        initial_state[12] = counter;

        // 4. Nonce (3 words)
        std::memcpy(&initial_state[13], nonce.data(), 12);

        // Copy to working state
        uint32_t state[16];
        std::memcpy(state, initial_state, 64);

        // 10 double-rounds = 20 rounds total
        for (int i = 0; i < 10; ++i) {
            // Column rounds
            quarter_round(state, 0, 4, 8, 12);
            quarter_round(state, 1, 5, 9, 13);
            quarter_round(state, 2, 6, 10, 14);
            quarter_round(state, 3, 7, 11, 15);

            // Diagonal rounds
            quarter_round(state, 0, 5, 10, 15);
            quarter_round(state, 1, 6, 11, 12);
            quarter_round(state, 2, 7, 8, 13);
            quarter_round(state, 3, 4, 9, 14);
        }

        // Add initial state back to final state
        uint32_t final_state[16];
        for (int i = 0; i < 16; ++i) {
            final_state[i] = state[i] + initial_state[i];
        }

        // Convert 16 32-bit words (64 bytes) to raw byte array
        std::vector<uint8_t> keystream(64);
        std::memcpy(keystream.data(), final_state, 64);
        return keystream;
    }

public:
    // Encrypt / Decrypt stream (symmetric XOR operations)
    static std::vector<uint8_t> process(const std::vector<uint8_t>& input, const std::vector<uint8_t>& key, const std::vector<uint8_t>& nonce, uint32_t initial_counter = 1) {
        std::vector<uint8_t> output(input.size());
        uint32_t counter = initial_counter;

        for (size_t i = 0; i < input.size(); i += 64) {
            std::vector<uint8_t> keystream = block(key, counter, nonce);
            size_t chunk_size = std::min(static_cast<size_t>(64), input.size() - i);

            for (size_t j = 0; j < chunk_size; ++j) {
                output[i + j] = input[i + j] ^ keystream[j];
            }
            counter++;
        }

        return output;
    }
};




std::vector<uint8_t> chacha20_process(
    const std::vector<uint8_t>& input, 
    const std::vector<uint8_t>& key, 
    const std::vector<uint8_t>& nonce, 
    uint32_t initial_counter
) {
    return ChaCha20Engine::process(input, key, nonce, initial_counter);
}


