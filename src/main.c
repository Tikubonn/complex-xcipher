
#include <io.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "complex-xcipher.h"

static int parse_uint_as_decimal (const char *source, uintmax_t *valuep){
  uintmax_t value = 0;
  for (size_t i = 0; source[i] != '\0'; i++){
    if ('0' <= source[i] && source[i] <= '9'){
      value *= 10;
      value += source[i] - '0';
    }
    else {
      fprintf(stderr, "Invalid char %c detected from \"%s\" when parse as uint(decimal).\n", source[i], source);
      return 1;
    }
  }
  *valuep = value;
  return 0;
}

static int parse_uint_as_hex (const char *source, uintmax_t *valuep){
  uintmax_t value = 0;
  if (source[0] != '\0'){
    for (size_t i = 0; source[i] != '\0'; i++){
      if ('0' <= source[i] && source[i] <= '9'){
        value *= 16;
        value += source[i] - '0';
      }
      else 
      if ('a' <= source[i] && source[i] <= 'f'){
        value *= 16;
        value += source[i] - 'a';
      }
      else 
      if ('A' <= source[i] && source[i] <= 'F'){
        value *= 16;
        value += source[i] - 'A';
      }
      else {
        fprintf(stderr, "Invalid char %c detected from \"%s\" when parse as uint(hexadecimal).\n", source[i], source);
        return 1;
      }
    }
    *valuep = value;
    return 0;
  }
  else {
    fprintf(stderr, "Given an empty string when parse as uint(hexadecimal).\n");
    return 1;
  }
}

static int parse_uint (const char *source, uintmax_t *valuep){
  if (source[0] == '0'){
    if (source[1] == 'x'){
      return parse_uint_as_hex(source +2, valuep);
    }
    else {
      return parse_uint_as_decimal(source, valuep);
    }
  }
  else 
  if ('1' <= source[0] && source[0] <= '9'){
    return parse_uint_as_decimal(source, valuep);
  }
  else {
    fprintf(stderr, "Invalid char %c detected from \"%s\" when parse as uint.\n", source[0], source);
    return 1;
  }
}

#ifndef MIN
#define MIN(a, b) ((a)<(b)?(a):(b))
#endif

static int parse_keys (const char *source, complex_xcipher_key keys[COMPLEX_XCIPHER_KEYS_LENGTH]){
  if (source[0] == '0' && source[1] == 'x'){
    const char *src = source +2;
    for (size_t i = 0; i < COMPLEX_XCIPHER_KEYS_LENGTH; i++){
      keys[i] = 0;
    }
    size_t srclen = strlen(src);
    for (size_t i = 0; i < COMPLEX_XCIPHER_KEYS_LENGTH; i++){
      char srcpart[sizeof(complex_xcipher_key) * 2 + 1] = {'\0'};
      size_t ibegin = MIN(srclen, i * sizeof(complex_xcipher_key) * 2);
      size_t iend = MIN(srclen, (i + 1) * sizeof(complex_xcipher_key) * 2);
      if (ibegin < iend){
        memcpy(srcpart, src + ibegin, iend - ibegin);
        uintmax_t value;
        if (parse_uint_as_hex(srcpart, &value) == 0){
          keys[i] = value;
        }
        else {
          fprintf(stderr, "Could not parse \"%s\" as int (its part of \"%s\").\n", srcpart, source);
          return 1;
        }
      }
      else {
        keys[i] = 0;
      }
    }
    return 0;
  }
  else {
    fprintf(stderr, "Cipher keys prefix must be '0x': \"%s\"\n", source);
    return 1;
  }
}

typedef enum cipher_mode {
  CIPHER_MODE_ENCTYPT,
  CIPHER_MODE_DECTYPT
} cipher_mode;

typedef struct arguments {
  cipher_mode mode;
  complex_xcipher_keyset keyset;
  size_t position;
  size_t size;
  const char *input_file;
  const char *output_file;
  bool add_nul;
  bool help;
} arguments;

const char HELP_MESSAGE[] = "Usage: complex-xcipher [options] [file]\n"
"Provide encryption, decryption function with command line.\n"
"\n"
"Arguments:\n"
"  input-file  file to input as binary.\n"
"\n"
"Options:\n"
"  -o, --output-file               File to save the result.\n"
"  -d, --dectypt                   Switch mode to dectyption.\n"
"  -e, --enctypt                   Switch mode to enctyption.\n"
"  -k, --key 0x123...              Set cipher keys from long hexadecimal digits.\n"
"  -K, --auto-key 123...|0x123...  Gen cipher keys from an unsigned integer to set.\n"
"  -p, --position 123...|0x123...  Its enabled on decrypt mode, its start position of decrypted data.\n"
"  -s, --size 123...|0x123...      Its enabled on decrypt mode, its size of decrypted data.\n"
"  -N, --nul                       If its enabled, add a nul character at end.\n"
"  -h, --help                      dump help information then exit.";

static int parse_args (int argc, const char **argv, arguments *args){
  bool mode_was_given = false;
  bool keyset_was_setup = false;
  cipher_mode mode = CIPHER_MODE_DECTYPT;
  complex_xcipher_keyset keyset;
  size_t position = 0;
  size_t size = 0;
  const char *input_file = NULL;
  const char *output_file = NULL;
  bool add_nul = false;
  bool help = false;
  size_t index = 1;
  while (index < argc){
    if (strcmp(argv[index], "-o") == 0 ||
        strcmp(argv[index], "--output-file") == 0){
      if (index +1 < argc){
        if (output_file == NULL){
          output_file = argv[index +1];
          index += 2;
        }
        else {
          fprintf(stderr, "Already given an argument of %s\n", "-o, --output");
          return 1;
        }
      }
      else {
        fprintf(stderr, "Need more arguments after %s\n", "-o, --output");
        return 1;
      }
    }
    else 
    if (strcmp(argv[index], "-e") == 0 || 
        strcmp(argv[index], "--enctypt") == 0){
      if (!mode_was_given){
        mode = CIPHER_MODE_ENCTYPT;
        mode_was_given = true;
        index += 1;
      }
      else {
        fprintf(stderr, "Already given an argument of %s\n", "-e, --enctypt");
        return 1;
      }
    }
    else 
    if (strcmp(argv[index], "-d") == 0 || 
        strcmp(argv[index], "--dectypt") == 0){
      if (!mode_was_given){
        mode = CIPHER_MODE_DECTYPT;
        mode_was_given = true;
        index += 1;
      }
      else {
        fprintf(stderr, "Already given an argument of %s\n", "-d, --dectypt");
        return 1;
      }
    }
    else 
    if (strcmp(argv[index], "-k") == 0 ||
        strcmp(argv[index], "--key") == 0){
      if (index +1 < argc){
        if (!keyset_was_setup){
          complex_xcipher_key keys[COMPLEX_XCIPHER_KEYS_LENGTH];
          if (parse_keys(argv[index +1], keys) == 0){
            complex_xcipher_keyset_setup(keys, &keyset);
            keyset_was_setup = true;
            index += 2;
          }
          else {
            fprintf(stderr, "Could not parse \"%s\" as keys.\n", argv[index +1]);
            return 1;
          }
        }
        else {
          fprintf(stderr, "Already given an argument of %s\n", "-k, --key");
          return 1;
        }
      }
      else {
        fprintf(stderr, "Need more arguments after %s\n", "-k, --key");
        return 1;
      }
    }
    else 
    if (strcmp(argv[index], "-K") == 0 ||
        strcmp(argv[index], "--auto-key") == 0){
      if (index +1 < argc){
        if (!keyset_was_setup){
          uintmax_t key;
          if (parse_uint(argv[index +1], &key) == 0){
            complex_xcipher_keyset_auto_setup(key, &keyset);
            keyset_was_setup = true;
            index += 2;
          }
          else {
            fprintf(stderr, "Could not parse \"%s\" as key.\n", argv[index +1]);
            return 1;
          }
        }
        else {
          fprintf(stderr, "Already given an argument of %s\n", "-K, --auto-key");
          return 1;
        }
      }
      else {
        fprintf(stderr, "Need more arguments after %s\n", "-K, --auto-key");
        return 1;
      }
    }
    else 
    if (strcmp(argv[index], "-s") == 0 || 
        strcmp(argv[index], "--size") == 0){
      if (index +1 < argc){
        uintmax_t value;
        if (parse_uint(argv[index +1], &value) == 0){
          if (value <= SIZE_MAX){
            size = value;
            index += 2;
          }
          else {
            fprintf(stderr, "Parsed value is larger than SIZE_MAX(%zu): %llu\n", SIZE_MAX, value);
            return 1;
          }
        }
        else {
          fprintf(stderr, "parse_uint() was failed: \"%s\"\n", argv[index +1]);
          return 1;
        }
      }
      else {
        fprintf(stderr, "Need more arguments after %s\n", "-s, --size");
        return 1;
      }
    }
    else 
    if (strcmp(argv[index], "-p") == 0 || 
        strcmp(argv[index], "--position") == 0){
      if (index +1 < argc){
        uintmax_t value;
        if (parse_uint(argv[index +1], &value) == 0){
          if (value <= SIZE_MAX){
            position = value;
            index += 2;
          }
          else {
            fprintf(stderr, "Parsed value is larger than SIZE_MAX(%zu): %llu\n", SIZE_MAX, value);
            return 1;
          }
        }
        else {
          fprintf(stderr, "parse_uint() was failed: \"%s\"\n", argv[index +1]);
          return 1;
        }
      }
      else {
        fprintf(stderr, "Need more arguments after %s\n", "-p, --position");
        return 1;
      }
    }
    else 
    if (strcmp(argv[index], "-N") == 0 ||
        strcmp(argv[index], "--nul") == 0){
      if (!add_nul){
        add_nul = true;
        index += 1;
      }
      else {
        fprintf(stderr, "Already given an argument of %s\n", "-N, --nul");
        return 1;
      }
    }
    else 
    if (strcmp(argv[index], "-h") == 0 ||
        strcmp(argv[index], "--help") == 0){
      if (!help){
        help = true;
        index += 1;
      }
      else {
        fprintf(stderr, "Already given an argument of %s\n", "-h, --help");
        return 1;
      }
    }
    else {
      if (input_file == NULL){
        input_file = argv[index];
        index += 1;
      }
      else {
        fprintf(stderr, "Already given an argument of %s\n", "input-file");
        return 1;
      }
    }
  }
  if (!help && !keyset_was_setup){ //tmp.
    fprintf(stderr, "Never given a cipher key.\n");
    return 1;
  }
  if (add_nul && mode != CIPHER_MODE_ENCTYPT){ //tmp.
    fprintf(stderr, "%s options has supported by only encrypt-mode.\n", "-N, --nul");
    return 1;
  }
  args->mode = mode;
  args->position = position;
  args->size = size;
  args->input_file = input_file;
  args->output_file = output_file;
  args->add_nul = add_nul;
  args->help = help;
  memcpy(&(args->keyset), &keyset, sizeof(keyset));
  return 0;
}

#define BUFFER_SIZE 4096

static int read_all (FILE *file, void **datap, size_t *datasizep){
  uint8_t *data = NULL;
  size_t datasize = 0;
  while (true){
    uint8_t *data2 = realloc(data, datasize + BUFFER_SIZE);
    if (data2 != NULL){
      size_t readsize = fread(data2 + datasize, 1, BUFFER_SIZE, file);
      if (0 < readsize){
        data = data2;
        datasize += readsize;
      }
      else {
        if (ferror(file) == 0){
          data = data2;
          break;
        }
        else {
          char *errorinfo = strerror(errno);
          fprintf(stderr, "fread() was failed: \"%s\"\n", errorinfo);
          free(data2);
          return 1;
        }
      }
    }
    else {
      char *errorinfo = strerror(errno);
      fprintf(stderr, "realloc() to extend was failed: \"%s\"\n", errorinfo);
      free(data);
      return 1;
    }
  }
  if (0 < datasize){
    data = realloc(data, datasize);
    if (data != NULL){
      *datap = data;
      *datasizep = datasize;
      return 0;
    }
    else {
      char *errorinfo = strerror(errno);
      fprintf(stderr, "realloc() to shrink was failed: \"%s\"\n", errorinfo);
      free(data);
      return 1;
    }
  }
  else {
    *datap = NULL;
    *datasizep = 0;
    free(data);
    return 0;
  }
}

static int write_all (FILE *file, void *data, size_t datasize){
  size_t i = 0;
  while (i < datasize){
    size_t wrotesize = fwrite(data + i, 1, datasize - i, file);
    if (0 < wrotesize){
      i += wrotesize;
    }
    else {
      if (ferror(file) != 0){
        char *errorinfo = strerror(errno);
        fprintf(stderr, "fwrite() was failed: \"%s\"\n", errorinfo);
        return 1;
      }
    }
  }
  return 0;
}

int main (int argc, const char **argv){
  arguments args;
  if (parse_args(argc, argv, &args) == 0){
    if (args.help){
      fprintf(stdout, HELP_MESSAGE);
      fprintf(stdout, "\n");
      return 0;
    }
    else {
      FILE *input;
      if (args.input_file != NULL){
        input = fopen(args.input_file, "rb");
        if (input == NULL){
          char *errorinfo = strerror(errno);
          fprintf(stderr, "fopen() to \"%s\" was failed: \"%s\"\n", args.input_file, errorinfo);
          return 1;
        }
      }
      else {
        input = stdin;
        if (_setmode(_fileno(stdin), _O_BINARY) == -1){
          char *errorinfo = strerror(errno);
          fprintf(stderr, "fopen() to %s was failed: \"%s\"\n", "fileno(stdin)", errorinfo);
          return 1;
        }
      }
      FILE *output;
      if (args.output_file != NULL){
        output = fopen(args.output_file, "wb");
        if (output == NULL){
          char *errorinfo = strerror(errno);
          fprintf(stderr, "fopen() to \"%s\" was failed: \"%s\"\n", args.output_file, errorinfo);
          fclose(input);
          return 1;
        }
      }
      else {
        output = stdout;
        if (_setmode(_fileno(stdout), _O_BINARY) == -1){
          char *errorinfo = strerror(errno);
          fprintf(stderr, "fopen() to %s was failed: \"%s\"\n", "fileno(stdout)", errorinfo);
          return 1;
        }
      }
      void *data;
      size_t datasize;
      if (read_all(input, &data, &datasize) != 0){
        fprintf(stderr, "read_all() was failed.\n");
        return 1;
      }
      switch (args.mode){
        case CIPHER_MODE_ENCTYPT: {
          if (args.add_nul){
            data = realloc(data, datasize +1);
            ((uint8_t*)data)[datasize] = 0;
            datasize += 1;
          }
          size_t datasize2;
          if (complex_xcipher_calc_encrypted_data_size(datasize, &datasize2) != 0){
            fclose(input);
            fclose(output);
            return 1;
          }
          void *data2 = malloc(datasize2);
          if (data2 == NULL){
            char *errorinfo = strerror(errno);
            fprintf(stderr, "malloc() was failed: \"%s\"\n", errorinfo);
            fclose(input);
            fclose(output);
            return 1;
          }
          if (complex_xcipher_encrypt(data, datasize, &(args.keyset), data2, datasize2) != 0){
            fprintf(stderr, "complex_xcipher_encrypt() was failed.\n");
            fclose(input);
            fclose(output);
            return 1;
          }
          if (write_all(output, data2, datasize2) != 0){
            fprintf(stderr, "write_all() was failed.\n");
            fclose(input);
            fclose(output);
            return 1;
          }
          break;
        }
        case CIPHER_MODE_DECTYPT: {
          size_t datasize2;
          if (0 < args.size){
            datasize2 = args.size;
          }
          else {
            if (args.position <= datasize){
              datasize2 = datasize - args.position;
              fprintf(stderr, "Used the file size as decrypted data size, because never given an -s, --size argument.\n");
            }
            else {
              fprintf(stderr, "Given a position %zu is out of range: %zu\n", args.position, datasize);
              return 1;
            }
          }
          void *data2 = malloc(datasize2);
          if (data2 == NULL){
            char *errorinfo = strerror(errno);
            fprintf(stderr, "malloc() was failed: \"%s\"\n", errorinfo);
            fclose(input);
            fclose(output);
            return 1;
          }
          if (complex_xcipher_decrypt(args.position, datasize2, data, datasize, &(args.keyset), data2) != 0){
            fprintf(stderr, "complex_xcipher_decrypt() was failed.\n");
            fclose(input);
            fclose(output);
            return 1;
          }
          if (write_all(output, data2, datasize2) != 0){
            fprintf(stderr, "write_all() was failed.\n");
            fclose(input);
            fclose(output);
            return 1;
          }
          break;
        }
        default:
          fprintf(stderr, "Given an unknown cipher_mode: %d\n", args.mode);
          fclose(input);
          fclose(output);
          return 1;
      }
      fclose(input);
      fclose(output);
      return 0;
    }
  }
  else {
    return 1;
  }
}
