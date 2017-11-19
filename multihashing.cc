#include <node.h>
#include <node_buffer.h>
#include <v8.h>
#include <stdint.h>
#include <nan.h>

extern "C" {
    #include "bcrypt.h"
    #include "keccak.h"
    #include "quark.h"
    #include "scryptjane.h"
    #include "scryptn.h"
    #include "skein.h"
    #include "x11.h"
    #include "groestl.h"
    #include "blake.h"
    #include "fugue.h"
    #include "qubit.h"
    #include "hefty1.h"
    #include "shavite3.h"
    #include "cryptonight.h"
    #include "x13.h"
    #include "nist5.h"
    #include "sha1.h"
    #include "x15.h"
	#include "fresh.h"
}

#include "boolberry.h"

using namespace node;
using namespace v8;
using namespace Nan;

#define THROW_ERROR_EXCEPTION(x) Nan::ThrowError(x)

void quark(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    quark_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void x11(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x11_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void scrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
   if (info.Length() < 3)
       return THROW_ERROR_EXCEPTION("You must provide buffer to hash, N value, and R value");

   Local<Object> target = info[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");
    
   Local<Number> numn = info[1]->ToNumber();
   unsigned int nValue = numn->Value();
   Local<Number> numr = info[2]->ToNumber();
   unsigned int rValue = numr->Value();
   
   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);
   
   scrypt_N_R_1_256(input, output, nValue, rValue, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}



void scryptn(const Nan::FunctionCallbackInfo<v8::Value>& info) {
   if (info.Length() < 2)
       return THROW_ERROR_EXCEPTION("You must provide buffer to hash and N factor.");

   Local<Object> target = info[0]->ToObject();

   if(!Buffer::HasInstance(target))
       return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

   Local<Number> num = info[1]->ToNumber();
   unsigned int nFactor = num->Value();

   char * input = Buffer::Data(target);
   char output[32];

   uint32_t input_len = Buffer::Length(target);

   //unsigned int N = 1 << (getNfactor(input) + 1);
   unsigned int N = 1 << nFactor;

   scrypt_N_R_1_256(input, output, N, 1, input_len); //hardcode for now to R=1 for now


	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void scryptjane(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 5)
        return THROW_ERROR_EXCEPTION("You must provide two argument: buffer, timestamp as number, and nChainStarTime as number, nMin, and nMax");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("First should be a buffer object.");

    Local<Number> num = info[1]->ToNumber();
    int timestamp = num->Value();

    Local<Number> num2 = info[2]->ToNumber();
    int nChainStartTime = num2->Value();

    Local<Number> num3 = info[3]->ToNumber();
    int nMin = num3->Value();

    Local<Number> num4 = info[4]->ToNumber();
    int nMax = num4->Value();

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    scryptjane_hash(input, input_len, (uint32_t *)output, GetNfactorJane(timestamp, nChainStartTime, nMin, nMax));

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void keccak(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    unsigned int dSize = Buffer::Length(target);

    keccak_hash(input, output, dSize);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}


void bcrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    bcrypt_hash(input, output);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void skein(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    
    skein_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}


void groestl(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    groestl_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}


void groestlmyriad(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    groestlmyriad_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}


void blake(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    blake_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}


void fugue(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    fugue_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}


void qubit(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    qubit_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}


void hefty1(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    hefty1_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}


void shavite3(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    shavite3_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void cryptonight(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    bool fast = false;

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");
    
    if (info.Length() >= 2) {
        if(!info[1]->IsBoolean())
            return THROW_ERROR_EXCEPTION("Argument 2 should be a boolean");
        fast = info[1]->ToBoolean()->BooleanValue();
    }

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];
    
    uint32_t input_len = Buffer::Length(target);

    if(fast)
        cryptonight_fast_hash(input, output, input_len);
    else
        cryptonight_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void x13(const Nan::FunctionCallbackInfo<v8::Value>& info) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x13_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}
void boolberry(const Nan::FunctionCallbackInfo<v8::Value>& info) {

    if (info.Length() < 2)
        return THROW_ERROR_EXCEPTION("You must provide two arguments.");

    Local<Object> target = info[0]->ToObject();
    Local<Object> target_spad = info[1]->ToObject();
    uint32_t height = 1;

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument 1 should be a buffer object.");

    if(!Buffer::HasInstance(target_spad))
        return THROW_ERROR_EXCEPTION("Argument 2 should be a buffer object.");

    if(info.Length() >= 3)
        if(info[2]->IsUint32())
            height = info[2]->ToUint32()->Uint32Value();
        else
            return THROW_ERROR_EXCEPTION("Argument 3 should be an unsigned integer.");

    char * input = Buffer::Data(target);
    char * scratchpad = Buffer::Data(target_spad);
    char output[32];

    uint32_t input_len = Buffer::Length(target);
    uint64_t spad_len = Buffer::Length(target_spad);

    boolberry_hash(input, input_len, scratchpad, spad_len, output, height);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void nist5(const Nan::FunctionCallbackInfo<v8::Value>& info) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    nist5_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void sha1(const Nan::FunctionCallbackInfo<v8::Value>& info) {

    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    sha1_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void x15(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    x15_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

void fresh(const Nan::FunctionCallbackInfo<v8::Value>& info) {
    if (info.Length() < 1)
        return THROW_ERROR_EXCEPTION("You must provide one argument.");

    Local<Object> target = info[0]->ToObject();

    if(!Buffer::HasInstance(target))
        return THROW_ERROR_EXCEPTION("Argument should be a buffer object.");

    char * input = Buffer::Data(target);
    char output[32];

    uint32_t input_len = Buffer::Length(target);

    fresh_hash(input, output, input_len);

	v8::Local<v8::Value> returnValue = Nan::CopyBuffer((char*)output, 32).ToLocalChecked();
	info.GetReturnValue().Set(
		returnValue
	);
}

NAN_MODULE_INIT(init) {
    Nan::Set(target, Nan::New("quark").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(quark)).ToLocalChecked());
    Nan::Set(target, Nan::New("x11").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x11)).ToLocalChecked());
    Nan::Set(target, Nan::New("scrypt").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(scrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("scryptn").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(scryptn)).ToLocalChecked());
    Nan::Set(target, Nan::New("scryptjane").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(scryptjane)).ToLocalChecked());
    Nan::Set(target, Nan::New("keccak").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(keccak)).ToLocalChecked());
    Nan::Set(target, Nan::New("bcrypt").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(bcrypt)).ToLocalChecked());
    Nan::Set(target, Nan::New("skein").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(skein)).ToLocalChecked());
    Nan::Set(target, Nan::New("groestl").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(groestl)).ToLocalChecked());
    Nan::Set(target, Nan::New("groestlmyriad").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(groestlmyriad)).ToLocalChecked());
    Nan::Set(target, Nan::New("blake").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(blake)).ToLocalChecked());
    Nan::Set(target, Nan::New("fugue").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(fugue)).ToLocalChecked());
    Nan::Set(target, Nan::New("qubit").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(qubit)).ToLocalChecked());
    Nan::Set(target, Nan::New("hefty1").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(hefty1)).ToLocalChecked());
    Nan::Set(target, Nan::New("shavite3").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(shavite3)).ToLocalChecked());
    Nan::Set(target, Nan::New("cryptonight").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(cryptonight)).ToLocalChecked());
    Nan::Set(target, Nan::New("x13").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x13)).ToLocalChecked());
    Nan::Set(target, Nan::New("boolberry").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(boolberry)).ToLocalChecked());
    Nan::Set(target, Nan::New("nist5").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(nist5)).ToLocalChecked());
    Nan::Set(target, Nan::New("sha1").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(sha1)).ToLocalChecked());
    Nan::Set(target, Nan::New("x15").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(x15)).ToLocalChecked());
    Nan::Set(target, Nan::New("fresh").ToLocalChecked(), Nan::GetFunction(Nan::New<FunctionTemplate>(fresh)).ToLocalChecked());
}

NODE_MODULE(multihashing, init)
