new Vue({
    el: '#app',
    data: {
        products: [],
        
        selectedCategory: '',
        filteredProducts: [],
        originalProducts: {},
        
        serverBaseUrl: 'http://127.0.0.1:3000',
        errorMessage: ''
    },
    methods: {
        fetchProducts: function() {
            axios.get('http://127.0.0.1:3000/products')
                .then(response => {
                    this.products = response.data.map(product => {
                        product.isEditing = false;
                        return product;
                    });
                    this.filteredProducts = this.products;
                })
                .catch(error => {
                    console.error('Error al obtener los productos:', error);
                    this.errorMessage = 'Hubo un problema al obtener los productos. Por favor, intenta nuevamente más tarde.';
                });
                
        },
        modifyProduct: function(product) {
            window.location.href = `editar_producto.html?id=${product._id}`;
        },
        deleteProduct: function(productId) {
            if (confirm('¿Estás seguro de que deseas eliminar este producto?')) {
                axios.delete(`http://127.0.0.1:3000/products/${productId}`)
                    .then(response => {
                        if (response.status === 200) {
                            alert('Producto eliminado con éxito.');
                            this.fetchProducts();
                        } else {
                            throw new Error('Respuesta no exitosa del servidor');
                        }
                    })
                    .catch(error => {
                        console.error('Error al eliminar el producto:', error);
                        alert('Error al eliminar el producto.');
                    });
            }
        },
        filterByCategory: function() {
            if (this.selectedCategory === '') {
                this.filteredProducts = this.products;
            } else {
                this.filteredProducts = this.products.filter(product => product.category === this.selectedCategory);
            }
        },
        toggleEdit: function(product) {
            product.isEditing = !product.isEditing;
            if (product.isEditing) {
                this.originalProducts[product._id] = { ...product };
            } else {
                Object.assign(product, this.originalProducts[product._id]);
            }
        },
        saveChanges: function(product) {
            const updatedProduct = { ...product };
            delete updatedProduct.isEditing;

            axios.put(`http://127.0.0.1:3000/products/${product._id}`, product)
                .then(response => {
                    if (response.status === 200) {
                        alert('Producto actualizado con éxito.');
                        product.isEditing = false;
                        this.fetchProducts();
                    } else {
                        throw new Error('Respuesta no exitosa del servidor');
                    }
                })
                .catch(error => {
                    console.error('Error al actualizar el producto:', error);
                    alert('Error al actualizar el producto.');
                });
        },
        cancelEdit: function(product) {
            console.log("El método cancelEdit ha sido llamado");
            product.isEditing = false;
            Vue.set(this.filteredProducts, this.filteredProducts.indexOf(product), { ...this.originalProducts[product._id], isEditing: false });
        },
        updateImage: function(event, product) {
            const file = event.target.files[0];
            if (file) {
                const reader = new FileReader();
                reader.onload = (e) => {
                    product.imageUrl = e.target.result;
                };
                reader.readAsDataURL(file);
            }
        }},
        
        
        
    mounted: function() {
        this.fetchProducts();
        
    }
});
