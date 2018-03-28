#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

#include "cryptonight.h"
#include "cryptonight_light.h"

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void callback(char *data, void *hint) {
	free(data);
}

using namespace node;
using namespace v8;

extern "C" {
cryptonight_ctx* cryptonight_alloc_ctx(size_t use_fast_mem, size_t use_mlock, alloc_msg* msg);
size_t cryptonight_init(size_t use_fast_mem, size_t use_mlock, alloc_msg* msg);
}

NAN_METHOD(cryptonight) {

	bool variant = false;

	if (info.Length() < 2)
		return THROW_ERROR_EXCEPTION("You must provide 2 argument.");

	if (info.Length() >= 2) {
		if (!info[1]->IsBoolean())
			return THROW_ERROR_EXCEPTION("Argument 2 should be a boolean");
		variant = info[1]->ToBoolean()->BooleanValue();
	}

	Local<Object> target = info[0]->ToObject();

	if (!Buffer::HasInstance(target))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	char * input = Buffer::Data(target);
	char output[32];

	uint32_t input_len = Buffer::Length(target);

	alloc_msg msg = { 0 };
	int res = cryptonight_init(1, 1, &msg);
	cryptonight_ctx *ctx0 = cryptonight_alloc_ctx(0, 1, &msg);
	if (ctx0 == nullptr)
	{
		return THROW_ERROR_EXCEPTION("Alloc cryptonight_ctx faild.");
	}
	cryptonight_hash(0x80000, MEMORY, 0, 1, variant, input, input_len, output, ctx0);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

#if 0
NAN_METHOD(cryptonight_light) {

	bool fast = false;

	if (info.Length() < 1)
		return THROW_ERROR_EXCEPTION("You must provide one argument.");

	if (info.Length() >= 2) {
		if (!info[1]->IsBoolean())
			return THROW_ERROR_EXCEPTION("Argument 2 should be a boolean");
		fast = info[1]->ToBoolean()->BooleanValue();
	}

	Local<Object> target = info[0]->ToObject();

	if (!Buffer::HasInstance(target))
		return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

	char * input = Buffer::Data(target);
	char output[32];

	uint32_t input_len = Buffer::Length(target);

	if (fast)
		cryptonight_light_fast_hash(input, output, input_len);
	else
		cryptonight_light_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer(output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

Nan::Set(target, Nan::New("cryptonight_light").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight_light)).ToLocalChecked());
#endif

#if 1
NAN_MODULE_INIT(init) {
	Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(),
		Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
}

NODE_MODULE(multihashing, init
)

#else

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

static int x2d(char x)
{
	int d = 0;

	if (isdigit(x))
	{
		d = x - '0';
	}
	else if (isxdigit(x))
	{
		d = toupper(x) - 'A' + 0xA;
	}

	return d;
}
static void StringToByteArray(
	const char* string_in,
	char* byte_array_out,
	int   byte_array_length_in,
	int * byte_array_length_out
)
{
	int byte_array_idx = 0;
	if (string_in == NULL ||
		byte_array_length_in == 0 ||
		byte_array_out == NULL ||
		byte_array_length_out == NULL)
	{
		return;
	}
	for (byte_array_idx = 0; byte_array_idx < byte_array_length_in; ++byte_array_idx)
	{
		if (*(string_in) == '\0' ||
			*(string_in + 1) == '\0')
		{
			break;
		}
		if (!isxdigit(*(string_in)) ||
			!isxdigit(*(string_in + 1)))
		{
			break;
		}

		byte_array_out[byte_array_idx] = x2d(*(string_in)) << 4 | x2d(*(string_in + 1));
		string_in += 2;
	}
	*byte_array_length_out = byte_array_idx;
}

bool TestCryptonight(void)
{
	const char inputStr[] = "ae97e8d505cb6b3e7e21366cf30903ac9f3783c9e763fa650e7adaeb4cd638c72c0fbcfee404004002d16d7fee1e39054453d27ce1d5a1ae8fac5b0b1ff335386e359558d57180c03c07";
	char result[] = "b1bda297564ae4707088bafe6d4e1da677d3f81c2e0da27eb858fa3420f00";

	char input_byte_array[1600] = { 0 };
	int input_byte_array_length = 0;
	StringToByteArray(inputStr, input_byte_array, sizeof(input_byte_array), &input_byte_array_length);

	char output_byte_array[1600] = { 0 };
	int output_byte_array_length = 0;
	StringToByteArray(result, output_byte_array, sizeof(output_byte_array), &output_byte_array_length);

	int fast = 0;

	char output[1000] = { 0 };

	alloc_msg msg = { 0 };
	cryptonight_ctx *ctx0 = cryptonight_alloc_ctx(0, 1, &msg);

	// if (fast)
	// 	cryptonight_fast_hash(input_byte_array, output, input_byte_array_length);
	// else
	 	// cryptonight_hash(0x80000, MEMORY, 0, 1, 0, input_byte_array, input_byte_array_length, output, ctx0);

	cryptonight_hash(0x80000, MEMORY, 0, 0, 0, "This is a test", 14, output, ctx0);
	int bResult = memcmp(output, "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b\x60\xd4\x35\x54\xae\x10\x58\x02\xc5\xf5\xd8\xa9\xb3\x25\x36\x49\xc0\xbe\x66\x05", 32) == 0;

	cryptonight_hash(0x80000, MEMORY, 0, 1, 0, "This is a test", 14, output, ctx0);
	bResult &= memcmp(output, "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b\x60\xd4\x35\x54\xae\x10\x58\x02\xc5\xf5\xd8\xa9\xb3\x25\x36\x49\xc0\xbe\x66\x05", 32) == 0;

	// cryptonight_fast_hash("This is a test", output, 14);
	// bResult &= memcmp(output, "\xa0\x84\xf0\x1d\x14\x37\xa0\x9c\x69\x85\x40\x1b\x60\xd4\x35\x54\xae\x10\x58\x02\xc5\xf5\xd8\xa9\xb3\x25\x36\x49\xc0\xbe\x66\x05", 32) == 0;
	return bResult;
}

int main(int argc, char *argv[])
{
#if 1
	alloc_msg msg = { 0 };
	int res = cryptonight_init(1, 1, &msg);

	if (TestCryptonight())
	{
		printf("TestCryptonight Pass\n");
	}
	else
	{
		printf("TestCryptonight Faild\n");
	}
	getchar();
#endif
}

#endif