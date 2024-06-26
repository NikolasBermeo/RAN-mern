const express = require("express");
const app = express();
const mysql = require("mysql");
const cors = require("cors");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
app.use(express.json({ limit: '10mb' }));

app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "rainanectar"
});

// Middleware para verificar la autenticación
const verificarAutenticacion = (req, res, next) => {
  const token = req.headers.authorization;

  if (!token) {
    return res.status(401).json({ error: 'No autorizado' });
  }

  try {
    const decoded = jwt.verify(token, 'secreto');
    req.user = decoded;
    next();
  } catch (error) {
    console.error('Error de autenticación:', error);
    return res.status(401).json({ error: 'Token inválido' });
  }
};

// Ruta para iniciar sesión
app.post('/iniciar-sesion', (req, res) => {
  const { NombreUsuario, Contrasena } = req.body;

  const query = 'SELECT * FROM usuarios WHERE NombreUsuario = ?';
  db.query(query, [NombreUsuario], (error, results) => {
    if (error) {
      console.error('Error al consultar la base de datos:', error);
      res.status(500).json({ error: 'Error en el servidor' });
      return;
    }

    if (results.length === 0) {
      res.status(401).json({ error: 'Credenciales inválidas' });
      return;
    }

    const usuario = results[0];
    bcrypt.compare(Contrasena, usuario.Contrasena, (err, match) => {
      if (err) {
        console.error('Error al comparar la contraseña:', err);
        res.status(500).json({ error: 'Error en el servidor' });
        return;
      }

      if (!match) {
        res.status(401).json({ error: 'Credenciales inválidas' });
        return;
      }

      const token = jwt.sign({ UsuarioID: usuario.UsuarioID }, 'secreto', { expiresIn: '1h' });

      res.status(200).json({ token });
    });
  });
});

// Ruta protegida del perfil
app.get('/perfil', verificarAutenticacion, (req, res) => {
  const { UsuarioID } = req.user;

  const query = 'SELECT NombreUsuario, Rol FROM usuarios WHERE UsuarioID = ?';
  db.query(query, [UsuarioID], (error, results) => {
    if (error) {
      console.error('Error al obtener perfil del usuario:', error);
      res.status(500).json({ error: 'Error en el servidor' });
      return;
    }

    if (results.length === 0) {
      res.status(404).json({ error: 'Usuario no encontrado' });
      return;
    }

    const { NombreUsuario, Rol } = results[0];
    res.status(200).json({ NombreUsuario, Rol });
  });
});

// Ruta para cerrar sesión
app.post('/cerrar-sesion', (req, res) => {
  res.status(200).json({ mensaje: 'Sesión cerrada exitosamente' });
});

// Ruta para registrar usuario
app.post('/registrar', async (req, res) => {
  const { Nombres, Apellidos, Correo, NombreUsuario, Contrasena, TipoDocumento, Documento } = req.body;

  try {
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(Contrasena, saltRounds);

    const query = 'INSERT INTO usuarios (Nombres, Apellidos, Correo, NombreUsuario, Contrasena, TipoDocumento, Documento, Rol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)';
    const values = [Nombres, Apellidos, Correo, NombreUsuario, hashedPassword, TipoDocumento, Documento, 1];

    db.query(query, values, (error, results) => {
      if (error) {
        console.error('Error al insertar datos:', error);
        res.status(500).json({ error: 'Error al registrar el usuario' });
      } else {
        res.status(200).json({ mensaje: 'Registro exitoso' });
      }
    });
  } catch (error) {
    console.error('Error al encriptar la contraseña:', error);
    res.status(500).json({ error: 'Error al registrar el usuario' });
  }
});

// Endpoint para obtener productos
app.get('/api/products', (req, res) => {
  let sql = 'SELECT * FROM productos';
  const category = req.query.category;
  if (category) {
    sql += ` WHERE CategoriaID = ${category}`;
  }
  db.query(sql, (err, result) => {
    if (err) {
      res.status(500).json({ error: 'Error al obtener los productos' });
      throw err;
    }
    res.json(result);
  });
});

// Endpoint para obtener una imagen por ID
app.get('/api/productImage/:id', (req, res) => {
  const productId = req.params.id;
  const sql = 'SELECT Imagen FROM productos WHERE ProductoID = ?';
  db.query(sql, [productId], (err, result) => {
    if (err) {
      res.status(500).json({ error: 'Error al obtener la imagen del producto' });
      throw err;
    }
    if (result.length > 0) {
      const image = result[0].Imagen;
      res.set('Content-Type', 'image/jpeg');
      res.send(image);
    } else {
      res.status(404).json({ error: 'Imagen no encontrada' });
    }
  });
});

// CRUD Usuarios

app.post("/create", (req, res) => {
  const { Nombres, Apellidos, Correo, NombreUsuario, Contrasena, TipoDocumento, Documento, Rol } = req.body;

  bcrypt.hash(Contrasena, 10, (err, hash) => {
    if (err) {
      console.log(err);
      res.status(500).send("Error interno del servidor");
      return;
    }

    db.query('INSERT INTO usuarios (Nombres, Apellidos, Correo, NombreUsuario, Contrasena, TipoDocumento, Documento, Rol) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', 
      [Nombres, Apellidos, Correo, NombreUsuario, hash, TipoDocumento, Documento, Rol],
      (err, result) => {
        if (err) {
          console.log(err);
          res.status(500).send("Error interno del servidor");
        } else {
          res.send(result);
        }
      }
    );
  });
});

app.get("/usuarios", (req, res) => {
  db.query('SELECT * FROM usuarios', (err, result) => {
    if (err) {
      console.log(err);
    } else {
      res.send(result);
    }
  });
});

app.put("/update", (req, res) => {
  const { UsuarioID, Nombres, Apellidos, Correo, NombreUsuario, Contrasena, TipoDocumento, Documento, Rol } = req.body;

  db.query('UPDATE usuarios SET Nombres = ?, Apellidos = ?, Correo = ?, NombreUsuario = ?, Contrasena = ?, TipoDocumento = ?, Documento = ?, Rol = ? WHERE UsuarioID = ?', 
    [Nombres, Apellidos, Correo, NombreUsuario, Contrasena, TipoDocumento, Documento, Rol, UsuarioID],
    (err, result) => {
      if (err) {
        console.error(err);
        res.status(500).send("Error interno del servidor");
      } else {
        res.send(result);
      }
    }
  );
});

app.delete("/delete/:UsuarioID", (req, res) => {
  const UsuarioID = req.params.UsuarioID;

  db.query('DELETE FROM usuarios WHERE UsuarioID = ?', UsuarioID, (err, result) => {
    if (err) {
      console.error(err);
      res.status(500).send("Error interno del servidor");
    } else {
      res.send(result);
    }
  });
});

app.put('/actualizar', verificarAutenticacion, async (req, res) => {
  const { Nombres, Apellidos, Correo, NombreUsuario, Contrasena, TipoDocumento, Documento } = req.body;
  const { UsuarioID } = req.user;

  try {
    let hashedPassword;
    if (Contrasena) {
      const saltRounds = 10;
      hashedPassword = await bcrypt.hash(Contrasena, saltRounds);
    }

    const query = 'UPDATE usuarios SET Nombres = ?, Apellidos = ?, Correo = ?, NombreUsuario = ?, Contrasena = ?, TipoDocumento = ?, Documento = ? WHERE UsuarioID = ?';
    const values = [Nombres, Apellidos, Correo, NombreUsuario, hashedPassword || Contrasena, TipoDocumento, Documento, UsuarioID];

    db.query(query, values, (error, results) => {
      if (error) {
        console.error('Error al actualizar datos:', error);
        res.status(500).json({ error: 'Error al actualizar el perfil del usuario' });
      } else {
        res.status(200).json({ mensaje: 'Perfil actualizado exitosamente' });
      }
    });
  } catch (error) {
    console.error('Error al actualizar el perfil del usuario:', error);
    res.status(500).json({ error: 'Error al actualizar el perfil del usuario' });
  }
});

// CRUD Productos
// CRUD Productos

app.post("/productos/create", (req, res) => {
  const { Nombre, Descripcion, Precio, CategoriaID, Imagen } = req.body;

  const query = 'INSERT INTO productos (Nombre, Descripcion, Precio, CategoriaID, Imagen) VALUES (?, ?, ?, ?, ?)';
  const values = [Nombre, Descripcion, Precio, CategoriaID, Imagen];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error al crear el producto:', err);
      res.status(500).json({ error: 'Error al crear el producto' });
    } else {
      res.status(200).json({ mensaje: 'Producto creado exitosamente' });
    }
  });
});

app.get("/productos", (req, res) => {
  db.query('SELECT * FROM productos', (err, result) => {
    if (err) {
      console.error('Error al obtener productos:', err);
      res.status(500).json({ error: 'Error al obtener productos' });
    } else {
      res.json(result);
    }
  });
});

app.put("/productos/update", (req, res) => {
  const { ProductoID, Nombre, Descripcion, Precio, CategoriaID, Imagen } = req.body;

  const query = 'UPDATE productos SET Nombre = ?, Descripcion = ?, Precio = ?, CategoriaID = ?, Imagen = ? WHERE ProductoID = ?';
  const values = [Nombre, Descripcion, Precio, CategoriaID, Imagen, ProductoID];

  db.query(query, values, (err, result) => {
    if (err) {
      console.error('Error al actualizar el producto:', err);
      res.status(500).json({ error: 'Error al actualizar el producto' });
    } else {
      res.status(200).json({ mensaje: 'Producto actualizado exitosamente' });
    }
  });
});
// Ruta para actualizar el stock después del pago
app.post('/api/updateStock', (req, res) => {
  const cartItems = req.body.cart;

  const queries = cartItems.map(item => {
    return new Promise((resolve, reject) => {
      const query = 'UPDATE productos SET Stock = Stock - ? WHERE ProductoID = ? AND Stock >= ?';
      const values = [item.cantidad, item.ProductoID, item.cantidad];

      db.query(query, values, (err, result) => {
        if (err) {
          reject(err);
        } else if (result.affectedRows === 0) {
          reject(new Error(`No hay suficiente stock para el producto con ID ${item.ProductoID}`));
        } else {
          resolve();
        }
      });
    });
  });

  Promise.all(queries)
    .then(() => {
      res.status(200).json({ mensaje: 'Stock actualizado exitosamente' });
    })
    .catch(error => {
      console.error('Error al actualizar el stock:', error);
      res.status(500).json({ error: 'Error al actualizar el stock' });
    });
});
app.delete("/productos/delete/:ProductoID", (req, res) => {
  const ProductoID = req.params.ProductoID;

  const query = 'DELETE FROM productos WHERE ProductoID = ?';

  db.query(query, [ProductoID], (err, result) => {
    if (err) {
      console.error('Error al eliminar el producto:', err);
      res.status(500).json({ error: 'Error al eliminar el producto' });
    } else {
      res.status(200).json({ mensaje: 'Producto eliminado exitosamente' });
    }
  });
});

app.listen(3001, () => {
  console.log("Servidor corriendo en el puerto 3001");
});

