const std = @import("std");
const expect = std.testing.expect;

const Base64 = struct {
    _table: *const [64]u8,

    pub fn init() Base64 {
        const upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const lower = "abcdefghijklmnopqrstuvwxyz";
        const numbers = "0123456789";
        const special_symbols = "+/";

        return Base64{
            ._table = upper ++ lower ++ numbers ++ special_symbols,
        };
    }

    pub fn encode(self: Base64, allocator: std.mem.Allocator, input: []const u8) ![]u8 {
        // Q: why do we allocate the result on heap?
        // A: because the string we return might be really large and we do not want to make a copy on return
        // also we can't just return a pointer to stack data because the data will be gone after we exit the scope

        const output_length = try calculateEncodeLength(input);
        var output = try allocator.alloc(u8, output_length);

        var counter: usize = 0;
        var output_index: usize = 0;
        var input_buffer = [3]u8{ 0, 0, 0 };

        for (input, 0..) |_, i| {
            input_buffer[counter] = input[i];
            counter += 1;

            if (counter == 3) {
                const chunk = self.encodeChunk(&input_buffer);

                output[output_index] = chunk[0];
                output[output_index + 1] = chunk[1];
                output[output_index + 2] = chunk[2];
                output[output_index + 3] = chunk[3];

                counter = 0;
                output_index += 4;
            }
        }

        if (counter == 0) {
            return output;
        }

        std.debug.print("There are {d} hanging bytes\n", .{counter});

        const hanging_chunk = self.encodeChunk(input_buffer[0..counter]);

        output[output_index] = hanging_chunk[0];
        output[output_index + 1] = hanging_chunk[1];
        output[output_index + 2] = hanging_chunk[2];
        output[output_index + 3] = hanging_chunk[3];

        return output;
    }

    fn encodeChunk(self: Base64, input: []const u8) [4]u8 {
        var output = [4]u8{ 0, 0, 0, 0 };

        if (input.len == 3) {
            output[0] = self.at(input[0] >> 2);
            output[1] = self.at(((input[0] & 0b00000011) << 4) ^ (input[1] >> 4));
            output[2] = self.at(((input[1] & 0b00001111) << 2) ^ (input[2] >> 6));
            output[3] = self.at(input[2] & 0b00111111);
        }

        if (input.len == 2) {
            output[0] = self.at(input[0] >> 2);
            output[1] = self.at(((input[0] & 0b00000011) << 4) ^ (input[1] >> 4));
            output[2] = self.at(((input[1] & 0b00001111) << 2));
            output[3] = '=';
        }

        if (input.len == 1) {
            output[0] = self.at(input[0] >> 2);
            output[1] = self.at(((input[0] & 0b00000011) << 4));
            output[2] = '=';
            output[3] = '=';
        }

        return output;
    }

    fn at(self: Base64, index: u8) u8 {
        return self._table[index];
    }
};

fn calculateEncodeLength(input: []const u8) !usize {
    var length: usize = 1;

    if (input.len >= 3) {
        length = try std.math.divCeil(usize, input.len, 3);
    }

    return length * 4;
}

fn calculateDecodeLength(input: []const u8) !usize {
    var length: usize = 1;

    if (input.len >= 4) {
        length = try std.math.divFloor(usize, input.len, 4);
    }

    return length * 3;
}

test "0 hanging bytes" {
    const base64 = Base64.init();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const encoded: []u8 = try base64.encode(allocator, "Hello world!");
    defer allocator.free(encoded);
    const expected = "SGVsbG8gd29ybGQh";

    try expect(std.mem.eql(u8, encoded, expected) == true);
}

test "2 hanging bytes" {
    const base64 = Base64.init();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const encoded: []u8 = try base64.encode(allocator, "Maria");
    defer allocator.free(encoded);
    const expected = "TWFyaWE=";

    try expect(std.mem.eql(u8, encoded, expected) == true);
}

test "1 hanging bytes" {
    const base64 = Base64.init();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const encoded: []u8 = try base64.encode(allocator, "bankaii");
    defer allocator.free(encoded);
    const expected = "YmFua2FpaQ==";

    try expect(std.mem.eql(u8, encoded, expected) == true);
}
