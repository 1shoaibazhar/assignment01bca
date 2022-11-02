package assignment01bca

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"math"
	"math/big"
	"strconv"
)

const rnd = 5 //static, irl an aglo that increments this target over the period of time for incrs miners. want time and block rate to remain the same
type Block struct{
    Hash [] uint8 //an alias for the unsigned integer 8 type ( uint8 )
    Data [] uint8
    PrevHash [] uint8
    Nonce int
}

type BlockChain struct{ // type to represent the BC
    blocks []*Block //array of pointer to blocks
    
}

type ProofOfWork struct{
    Block *Block
    Target *big.Int //target is the req described derived from rnd, big int for number larger than 64 bits
}



func NewProof(b *Block) *ProofOfWork{ //outputs a pointer to POW and takes ptr to a block
    target := big.NewInt(1) //casting 1 as new BigInt converting any int to bigInt
    target.Lsh(target, uint(256-rnd)) //256 no. of uint8s in our hashes, use target to shift the number of uint8s over by this number, LSH (left shift func)
    
    pow := &ProofOfWork{b, target} //put the target into an instance of POW
    
    return pow //calculating the target for a block 
    
}



//utility function
func ToHex (num int64) [] byte{  //to add nonce to the collective hash for POW
    buff := new(bytes.Buffer) ////creates new bytes buffer. new used to get the Value representing a pointer to a new zero value for the specified type
    err := binary.Write(buff, binary.BigEndian, num) //encodes the num into bytes. Bytes to be organised in BigEndian
    if err != nil {
        log.Panic(err)
    }
    
    return buff.Bytes() //returning bytes portion of buffer
}

//creating hash of the target+block 

//hashcash - preceding 20 bits to be 0 in the hash
func (pow *ProofOfWork) InitData(nonce int) [] uint8{
    data := bytes.Join( //using Join to create a cohesive set of uint8s
        [][]uint8{
            pow.Block.PrevHash,
            pow.Block.Data,
            ToHex(int64(nonce)),
            ToHex(int64(rnd)),
        },
        []uint8{}, //combined w uint8 to get  cohesive set of uint8s after combining everything to be returned
        )
    return data
}

//computational function 1-prepare data 2-convert to hash sha256 format 3-convert the hash into bigInt 4-compare the hash with our target bigInt inside of our POW struct
func (pow *ProofOfWork) MineBlock ()(int, []uint8){
    var intHash big.Int //to store hash in BigInt
    var hash [32]uint8
    
    nonce := 0
    
    for nonce < math.MaxInt64{ //virtually infinite loop
        data := pow.InitData(nonce) //1-preping the data
        hash = sha256.Sum256(data) //2- converting to hash
        
        intHash.SetBytes(hash[:])
        
        //4- compare to target
        if intHash.Cmp(pow.Target) == -1{   //hash>target, block mined
            break 
        } else {
            nonce++ 
        }
    }

    return nonce, hash[:]
    
}

//validate the block easier, than work portion being computationally expensive

func (pow *ProofOfWork) VerifyChain () bool{ //after the MineBlock func, we'll have the nonce that would allow us to calculate the hash that met the target that we wanted, 
    var intHash big.Int                                 //running that cycle one more time to show the hash is valid
    data := pow.InitData(pow.Block.Nonce)   //wrapping the data with the nonce calucltaed with pow
    
    hash := sha256.Sum256(data)
    intHash.SetBytes(hash[:])
    
    return intHash.Cmp(pow.Target) == -1 //<target
}

func (b *Block) CalculateHash(){
    info := bytes.Join([][]uint8{b.Data, b.PrevHash}, []uint8{}) //2d slice of uint8s
    hash := sha256.Sum256(info) //calucluatibg the hash of data+prevHash
    b.Hash = hash[:] //including the hash in the Block structure
}

func NewBlock (data string, prevHash [] uint8) *Block{  //takes data + prevHash of a block and outputs pointer to the next new block
    block := &Block{[]uint8{}, []uint8(data),prevHash, 0}  //using block constructor, for hash taking empty slice of uint8s, uint8(data) -> takes data string and converts it into uint8s, prevHash already passed as a uint8
    block.CalculateHash()
    
    //performing pow for every block being created
    pow := NewProof (block)
    nonce, hash := pow.MineBlock()
    
    block.Hash = hash[:]
    block.Nonce = nonce
    return block
    
}


func Genesis() *Block{
    return NewBlock("Genesis", []uint8{}) //empty slice of uint8s
}


//function to add the block to the chain
func(chain *BlockChain) AddBlock(data string){ //method to add a block to the chain, hence it gets the pointer to the chain
    prevBlock := chain.blocks[len(chain.blocks)-1] //knowing the prev block
    newBlock := NewBlock(data, prevBlock.Hash) //calling NewBlock method to create the block
    chain.blocks = append(chain.blocks, newBlock) //appending newBlock and then assigning new blocks to blockchain.blocks
}

//creating a Blockchain from Genesis
func InitBlockChain() *BlockChain{
    return &BlockChain{[]*Block{Genesis()}} //reference to a BC, with an array of Block with a call to Genesis func
}



func DisplayBlocks(chain *BlockChain){
    //chain := blockchain.InitBlockChain()
    for _, block := range chain.blocks{
        fmt. Printf("\n---------------------------------------\n")
        fmt. Printf("Previous Hash: %x\n", block.PrevHash)
        fmt. Printf("Data in Block: %s\n", block.Data)
        fmt. Printf("Hash: %x\n", block.Hash)
        
        //adding pow algo (consensus algo) to blocks
        pow := NewProof(block)
        fmt. Printf("Pow: %s\n", strconv.FormatBool(pow.VerifyChain())) //conv validation boolean output into string format
        fmt. Println()
        fmt. Printf("\n---------------------------------------\n")
       
    }
}


func changeBlock(block *Block){
    block.Data = []uint8("Updated")
}