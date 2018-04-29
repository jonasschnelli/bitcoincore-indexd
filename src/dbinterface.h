#ifndef DBINTERFACE_H
#define DBINTERFACE_H

#include <stdint.h>
#include <string>
#include <vector>


//! Interface for the database
class IndexDatabaseInterface
{
public:
    virtual ~IndexDatabaseInterface() {}

    virtual bool open(const std::string& path) = 0;
    virtual bool beginTXN() = 0;
    virtual bool commitTXN() = 0;
    virtual bool close() = 0;
    virtual bool put(const uint8_t* key, unsigned int key_len, const uint8_t* value, unsigned int value_len) = 0;
};

#endif // DBINTERFACE_H
