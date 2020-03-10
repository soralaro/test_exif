/** \file test-parse.c
 * \brief Completely parse all files given on the command line.
 *
 * Copyright (C) 2007 Hans Ulrich Niedermann <gp@n-dimensional.de>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, 
 * but WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details. 
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301  USA.
 *
 */

#include "libexif/exif-data.h"
#include "libexif/exif-system.h"
#include <libexif/exif-tag.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>>
#include <time.h>
#include "opencv2/opencv.hpp"
static unsigned entry_count;
/** Callback function handling an ExifEntry. */
static void content_foreach_func(ExifEntry *entry, void *UNUSED(callback_data))
{
    char buf[2000];

    exif_entry_get_value(entry, buf, sizeof(buf));
    printf("    Entry %u: %s (%s)\n"
           "      Size, Comps: %d, %d\n"
           "      Value: %s\n",
           entry_count,
           exif_tag_get_name(entry->tag),
           exif_format_get_name(entry->format),
           entry->size,
           (int)(entry->components),
           exif_entry_get_value(entry, buf, sizeof(buf)));
    ++entry_count;
}


/** Callback function handling an ExifContent (corresponds 1:1 to an IFD). */
static void data_foreach_func(ExifContent *content, void *callback_data)
{
    static unsigned content_count;
    entry_count = 0;
    printf("  Content %u: ifd=%d\n", content_count, exif_content_get_ifd(content));
    exif_content_foreach_entry(content, content_foreach_func, callback_data);
    ++content_count;
}

static void dump_makernote(ExifData *d) {
    ExifMnoteData *mn = exif_data_get_mnote_data(d);
    if (mn) {
        char buf[2000];
        int i;
        int num = exif_mnote_data_count(mn);
        printf("  MakerNote\n");
        for (i=0; i < num; ++i) {
            if (exif_mnote_data_get_value(mn, i, buf, sizeof(buf))) {
                const char *name = exif_mnote_data_get_name(mn, i);
                unsigned int id = exif_mnote_data_get_id(mn, i);
                if (!name)
                    name = "(unknown)";
                printf("    Entry %u: %u, %s\n"
                       "      Size: %u\n"
                       "      Value: %s\n", i, id, name, (unsigned)strlen(buf), buf);
            }
        }
    }
}

/** Run EXIF parsing test on the given file. */
static int test_parse(const char *filename, void *callback_data, int swap)
{
    ExifData *d;

    /* Skip over path to display only the file name */
    const char *fn = strrchr(filename, '/');
    if (fn)
        ++fn;
    else
        fn = filename;
    printf("File %s\n", fn);

    d = exif_data_new_from_file(filename);
    if (!d) {
        fprintf (stderr, "Could not load data from '%s'!\n", filename);
        return 0;
    }
    printf("Byte order: %s\n",
           exif_byte_order_get_name(exif_data_get_byte_order(d)));

    if (swap) {
        ExifByteOrder order = EXIF_BYTE_ORDER_INTEL;
        if (exif_data_get_byte_order(d) == order) {
            order = EXIF_BYTE_ORDER_MOTOROLA;
        }
        /* This switches the byte order of the entire EXIF data structure,
         * including the MakerNote */
        exif_data_set_byte_order(d, order);
        printf("New byte order: %s\n",
               exif_byte_order_get_name(exif_data_get_byte_order(d)));
    }

    exif_data_foreach_content(d, data_foreach_func, callback_data);

    dump_makernote(d);

    exif_data_unref(d);
    return 0;
}

static int  test_parse_2(const char *filename, void *callback_data)
{
    ExifData *d;

    /* Skip over path to display only the file name */
    const char *fn = strrchr(filename, '/');
    if (fn)
        ++fn;
    else
        fn = filename;
    printf("File %s\n", fn);

    d = exif_data_new_from_file(filename);
    if (!d) {
        fprintf (stderr, "Could not load data from '%s'!\n", filename);
        return -1;
    }
    ExifTag tag=EXIF_TAG_ORIENTATION;
    ExifEntry *entry= exif_data_get_entry(d,tag);
    if(entry!= nullptr) {
        content_foreach_func(entry, NULL);
        //printf("Byte order: %s\n",
        //      exif_byte_order_get_name(exif_data_get_byte_order(d)));

    }

    //exif_data_foreach_content(d, data_foreach_func, callback_data);

    //dump_makernote(d);

    exif_data_unref(d);
    return 0;
}


/** Callback function prototype for string parsing. */
typedef void (*test_parse_func) (const char *filename, void *callback_data, int swap);


/** Split string at whitespace and call callback with each substring. */
static void split_ws_string(const char *string, test_parse_func func, void *callback_data)
{
    const char *start = string;
    const char *p = start;
    for (;;) {
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r' || *p == '\0' ) {
            size_t len = p-start;
            if (len > 0) {
                /* emulate strndup */
                char *str =(char *) malloc(1+len);
                if (str) {
                    memcpy(str, start, len);
                    str[len] = '\0';
                    func(str, callback_data, 0);
                    free(str);
                    start = p+1;
                }
            } else {
                start = p+1;
            }
        }
        if (*p == '\0') {
            break;
        }
        p++;
    }
}


static const unsigned char g_Make[16] = "AF";
static const unsigned char g_Model[16] = "JerryJiu";
static const unsigned char g_Version[16] = "181203Release";

/* start of JPEG image data section */
static const unsigned int image_data_offset = 20;

/* raw EXIF header data */
static const unsigned char exif_header[] = {
 0xff, 0xd8, 0xff, 0xe1
};

/* GPS Version */
static const unsigned char g_GPSVersion[] = {
 0x02, 0x02, 0x00, 0x00
};

/* length of data in exif_header */
static const unsigned int exif_header_len = sizeof(exif_header);

/* byte order to use in the EXIF block */
#define FILE_BYTE_ORDER EXIF_BYTE_ORDER_INTEL

/* Get an existing tag, or create one if it doesn't exist */
static ExifEntry *init_tag(ExifData *exif, ExifIfd ifd, ExifTag tag) {
    ExifEntry *entry= nullptr;
    /* Return an existing tag if one exists */
    entry = exif_content_get_entry(exif->ifd[ifd], tag);
    if (entry== nullptr) {
        /* Allocate a new entry */
        entry = exif_entry_new();
        assert(entry != nullptr); /* catch an out of memory condition */
        entry->tag = tag; /* tag must be set before calling
     exif_content_add_entry */

        /* Attach the ExifEntry to an IFD */
        exif_content_add_entry(exif->ifd[ifd], entry);

        /* Allocate memory for the entry and fill with default data */
        exif_entry_initialize(entry, tag);

        /* Ownership of the ExifEntry has now been passed to the IFD.
         * One must be very careful in accessing a structure after
         * unref'ing it; in this case, we know "entry" won't be freed
         * because the reference count was bumped when it was added to
         * the IFD.
         */
        exif_entry_unref(entry);
    }
    return entry;
}

/* Create a brand-new tag with a data field of the given length, in the
 * given IFD. This is needed when exif_entry_initialize() isn't able to create
 * this type of tag itself, or the default data length it creates isn't the
 * correct length.
 */
static ExifEntry *create_tag(ExifData *exif, ExifIfd ifd, ExifTag tag, size_t len) {
    void *buf;
    ExifEntry *entry;

    /* Create a memory allocator to manage this ExifEntry */
    ExifMem *mem = exif_mem_new_default();
    assert(mem != NULL); /* catch an out of memory condition */

    /* Create a new ExifEntry using our allocator */
    entry = exif_entry_new_mem(mem);
    assert(entry != NULL);

    /* Allocate memory to use for holding the tag data */
    buf = exif_mem_alloc(mem, len);
    assert(buf != NULL);

    /* Fill in the entry */
    entry->data = (unsigned char *) buf;
    entry->size = len;
    entry->tag = tag;
    entry->components = len;
    entry->format = EXIF_FORMAT_UNDEFINED;

    /* Attach the ExifEntry to an IFD */
    exif_content_add_entry(exif->ifd[ifd], entry);

    /* The ExifMem and ExifEntry are now owned elsewhere */
    exif_mem_unref(mem);
    exif_entry_unref(entry);

    return entry;
}

static int AF_SaveJpeg(char *pFilePath, unsigned char *pFrame, unsigned int nFrameLen, unsigned int nWidth, unsigned int nHeight)
{
    int nRet = 0;
    FILE *pFile = NULL;
    printf("AF_SaveJpeg\n");
    unsigned char *exif_data = NULL;
    unsigned int exif_data_len = 0;
    ExifEntry *entry = NULL;
    char pDataTime[20] = {0};
    int i = 0;
    time_t t = time(NULL);
    ExifData *exif = exif_data_new();
    if (!exif) {
        nRet = -1;
        goto ERR_EXIT;
    }

    /* Set the image options */
    exif_data_set_option(exif, EXIF_DATA_OPTION_FOLLOW_SPECIFICATION);
    exif_data_set_data_type(exif, EXIF_DATA_TYPE_COMPRESSED);
    exif_data_set_byte_order(exif, FILE_BYTE_ORDER);

    /* Create the mandatory EXIF fields with default data */
    exif_data_fix(exif);

    /* All these tags are created with default values by exif_data_fix() */
    /* Change the data to the correct values for this image. */
    entry = init_tag(exif, EXIF_IFD_EXIF, EXIF_TAG_PIXEL_X_DIMENSION);
    exif_set_long(entry->data, FILE_BYTE_ORDER, nWidth);

    entry = init_tag(exif, EXIF_IFD_EXIF, EXIF_TAG_PIXEL_Y_DIMENSION);
    exif_set_long(entry->data, FILE_BYTE_ORDER, nHeight);

    entry = init_tag(exif, EXIF_IFD_EXIF, EXIF_TAG_COLOR_SPACE);
    exif_set_short(entry->data, FILE_BYTE_ORDER, 1);

    entry = create_tag(exif, EXIF_IFD_0, ExifTag(EXIF_TAG_ORIENTATION),2);
    entry->format=EXIF_FORMAT_SHORT;
    entry->components=1;
    exif_set_short(entry->data, FILE_BYTE_ORDER, 3);


    entry = create_tag(exif, EXIF_IFD_GPS, ExifTag(EXIF_TAG_GPS_VERSION_ID),
                       4 * exif_format_get_size(EXIF_FORMAT_BYTE));
    entry->format = EXIF_FORMAT_BYTE;
    entry->components = 4;
    for (i = 0; i < 4; i++) {
        exif_set_sshort(entry->data + i, FILE_BYTE_ORDER, g_GPSVersion[i]);
    }

    // 上海北纬 30度40分~31度53分 东经 120度51分~122度12分
    entry = create_tag(exif, EXIF_IFD_GPS, ExifTag(EXIF_TAG_GPS_LATITUDE_REF),
                       2 * exif_format_get_size(EXIF_FORMAT_ASCII));
    entry->format = EXIF_FORMAT_ASCII;
    entry->components = 2;
    memcpy(entry->data, "N", 2);// N北纬/S南纬

    entry = create_tag(exif, EXIF_IFD_GPS, ExifTag(EXIF_TAG_GPS_LATITUDE),
                       3 * exif_format_get_size(EXIF_FORMAT_RATIONAL));
    entry->format = EXIF_FORMAT_RATIONAL;
    entry->components = 3;
    ExifRational fir, mid, las;
    fir.numerator = 31;
    fir.denominator = 1;
    mid.numerator = 00;
    mid.denominator = 1;
    las.numerator = 00;
    las.denominator = 1;
    exif_set_rational(entry->data, FILE_BYTE_ORDER, fir);
    exif_set_rational(entry->data + 8, FILE_BYTE_ORDER, mid);
    exif_set_rational(entry->data + 16, FILE_BYTE_ORDER, las);

    entry = create_tag(exif, EXIF_IFD_GPS, ExifTag(EXIF_TAG_GPS_LONGITUDE_REF),
                       2 * exif_format_get_size(EXIF_FORMAT_ASCII));
    entry->format = EXIF_FORMAT_ASCII;
    entry->components = 2;
    memcpy(entry->data, "E", 2);// E东经/W西经

    entry = create_tag(exif, EXIF_IFD_GPS, ExifTag(EXIF_TAG_GPS_LONGITUDE),
                       3 * exif_format_get_size(EXIF_FORMAT_RATIONAL));
    entry->format = EXIF_FORMAT_RATIONAL;
    entry->components = 3;
    fir.numerator = 121;
    fir.denominator = 1;
    mid.numerator = 0;
    mid.denominator = 1;
    las.numerator = 0;
    las.denominator = 1;
    exif_set_rational(entry->data, FILE_BYTE_ORDER, fir);
    exif_set_rational(entry->data + 8, FILE_BYTE_ORDER, mid);
    exif_set_rational(entry->data + 16, FILE_BYTE_ORDER, las);

    // 绝对-海平面
    entry = create_tag(exif, EXIF_IFD_GPS, ExifTag(EXIF_TAG_GPS_ALTITUDE_REF),
                       1 * exif_format_get_size(EXIF_FORMAT_BYTE));
    entry->format = EXIF_FORMAT_BYTE;
    entry->components = 1;
    exif_set_short(entry->data, FILE_BYTE_ORDER, 0);// 0-海面上 1-海面下

    // 高度
    entry = create_tag(exif, EXIF_IFD_GPS, ExifTag(EXIF_TAG_GPS_ALTITUDE),
                       1 * exif_format_get_size(EXIF_FORMAT_RATIONAL));
    entry->format = EXIF_FORMAT_RATIONAL;
    entry->components = 1;
    fir.numerator = 100;
    fir.denominator = 11;
    exif_set_rational(entry->data, FILE_BYTE_ORDER, fir);

    //GPS速度单位K KM/H
    entry = create_tag(exif, EXIF_IFD_GPS, ExifTag(EXIF_TAG_GPS_SPEED_REF),
                       2 * exif_format_get_size(EXIF_FORMAT_ASCII));
    entry->format = EXIF_FORMAT_ASCII;
    entry->components = 2;
    memcpy(entry->data, "K", 2);

    //GPS速度值
    entry = create_tag(exif, EXIF_IFD_GPS, ExifTag(EXIF_TAG_GPS_SPEED), 1 * exif_format_get_size(EXIF_FORMAT_RATIONAL));
    entry->format = EXIF_FORMAT_RATIONAL;
    entry->components = 1;
    fir.numerator = 50;
    fir.denominator = 1;
    exif_set_rational(entry->data, FILE_BYTE_ORDER, fir);

    // 拍摄时间
    // EXIF_TAG_SUB_SEC_TIME EXIF_TAG_SUB_SEC_TIME_ORIGINAL EXIF_TAG_SUB_SEC_TIME_DIGITIZED 毫秒时间不写入
    entry = create_tag(exif, EXIF_IFD_EXIF, EXIF_TAG_DATE_TIME_ORIGINAL, 20 * exif_format_get_size(EXIF_FORMAT_ASCII));
    entry->format = EXIF_FORMAT_ASCII;
    entry->components = 20;

    struct tm stTime;
    localtime_r(&t, &stTime);

    snprintf(pDataTime, sizeof(pDataTime), "%04d-%02d-%02d %02d:%02d:%02d", stTime.tm_year + 1900, stTime.tm_mon + 1,
             stTime.tm_mday, stTime.tm_hour, stTime.tm_min, stTime.tm_sec);
    memcpy(entry->data, pDataTime, sizeof(pDataTime));

    // 数字化时间
    entry = create_tag(exif, EXIF_IFD_EXIF, EXIF_TAG_DATE_TIME_DIGITIZED, 20 * exif_format_get_size(EXIF_FORMAT_ASCII));
    entry->format = EXIF_FORMAT_ASCII;
    entry->components = 20;
    memcpy(entry->data, pDataTime, sizeof(pDataTime));

    //制造商
    entry = create_tag(exif, EXIF_IFD_0, EXIF_TAG_MAKE, sizeof(g_Make) * exif_format_get_size(EXIF_FORMAT_ASCII));
    entry->format = EXIF_FORMAT_ASCII;
    entry->components = sizeof(g_Make);
    memcpy(entry->data, g_Make, sizeof(g_Make));

    // 型号
    entry = create_tag(exif, EXIF_IFD_0, EXIF_TAG_MODEL, sizeof(g_Model) * exif_format_get_size(EXIF_FORMAT_ASCII));
    entry->format = EXIF_FORMAT_ASCII;
    entry->components = sizeof(g_Model);
    memcpy(entry->data, g_Model, sizeof(g_Model));

    // 修改时间
    entry = create_tag(exif, EXIF_IFD_0, EXIF_TAG_DATE_TIME, 20 * exif_format_get_size(EXIF_FORMAT_ASCII));
    entry->format = EXIF_FORMAT_ASCII;
    entry->components = 20;
    memcpy(entry->data, pDataTime, sizeof(pDataTime));

    // 软件
    entry = create_tag(exif, EXIF_IFD_0, EXIF_TAG_SOFTWARE,
                       sizeof(g_Version) * exif_format_get_size(EXIF_FORMAT_ASCII));
    entry->format = EXIF_FORMAT_ASCII;
    entry->components = sizeof(g_Version);
    memcpy(entry->data, g_Version, sizeof(g_Version));


    exif_data_save_data(exif, &exif_data, &exif_data_len);
    assert(exif_data != NULL);

    pFile = fopen(pFilePath, "wb+");
    if (!pFile) {
        nRet = -1;
        goto ERR_EXIT;
    }

    /* Write EXIF header */
    if (fwrite(exif_header, exif_header_len, 1, pFile) != 1) {
        nRet = -1;
        goto ERR_EXIT;
    }
    /* Write EXIF block length in big-endian order */
    if (fputc((exif_data_len + 2) >> 8, pFile) < 0) {
        nRet = -1;
        goto ERR_EXIT;
    }
    if (fputc((exif_data_len + 2) & 0xff, pFile) < 0) {
        nRet = -1;
        goto ERR_EXIT;
    }
    /* Write EXIF data block */
    if (fwrite(exif_data, exif_data_len, 1, pFile) != 1) {
        nRet = -1;
        goto ERR_EXIT;
    }
    /* Write JPEG image data, skipping the non-EXIF header */
    if (fwrite(pFrame + image_data_offset, nFrameLen - image_data_offset, 1, pFile) != 1) {
        nRet = -1;
        goto ERR_EXIT;
    }

    ERR_EXIT:
    if (pFile) {
        fclose(pFile);
    }
    if (exif_data) {
        free(exif_data);
    }
    if (exif) {
        exif_data_unref(exif);
    }

    return nRet;
}

/** Main program. */
int main(const int argc, const char *argv[])
{
    void *callback_data = NULL;
    if(argc<2)
    {
        printf("please input jpeg file path!\n");
        return  0;
    }
    cv::Mat mat=cv::imread(argv[1]);
    cv::imwrite("cv_dst.jpg",mat);
    //if(-1==test_parse(argv[1], callback_data,0))
    if(-1==test_parse_2(argv[1], callback_data))
    {
        FILE *pFile = NULL;
        printf("fopen %s\n",argv[1]);
        pFile = fopen(argv[1], "rb");
        if (pFile) {
            fseek(pFile,0L,SEEK_END);
            int file_size=ftell(pFile);
            unsigned char *buf=new unsigned char[file_size];
            fseek(pFile,0L,SEEK_SET);
            fread(buf,1,file_size,pFile);
            printf("file_size=%d\n",file_size);
            AF_SaveJpeg("./dst.jpg", buf, file_size, 1280, 720);
            fclose(pFile);
            delete [] buf;
        }

    }

    return 0;
}

